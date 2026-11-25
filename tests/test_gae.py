import warnings
from datetime import datetime, timedelta, timezone

import pytest
import torch

warnings.filterwarnings("ignore", category=FutureWarning)

from slave.graph.detector import Cadence, collect_snapshots, size_bucket, train_gae  # noqa: E402
from slave.graph.gae import ALL_REL, HeteroGAE, loss_fn, node_errors  # noqa: E402
from slave.graph.snapshot import AGENT_BASE_DIM, SESSION_AGG_DIM, RELATIONS, SessionGraphs, rev  # noqa: E402
from slave.schema import Event, EventKind, NodeType, Trust  # noqa: E402
from slave.scoring.fastpath import train as train_fast  # noqa: E402
from slave.scoring.hybrid import HybridScorer  # noqa: E402
from slave.sim.attacks import ATTACKS  # noqa: E402
from slave.sim.swarm import generate  # noqa: E402

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)


def ev(i, kind, src, dst=None, sec=None, **kw):
    return Event(event_id=f"s:{i:06d}", session_id="s", ts=T0 + timedelta(seconds=sec if sec is not None else i),
                 kind=kind, src_id=src, dst_id=dst, **kw)


def small_session():
    return [
        ev(0, EventKind.SPAWN, "user", "p", dst_role="planner", dst_type=NodeType.AGENT, spawn_depth=0),
        ev(1, EventKind.SPAWN, "p", "a", dst_role="data_analyst", dst_type=NodeType.AGENT, spawn_depth=1),
        ev(2, EventKind.MSG_SEND, "p", "a", token_count=100, trust=Trust.SYSTEM),
        ev(3, EventKind.MSG_SEND, "p", "a", token_count=300, trust=Trust.UNTRUSTED),
        ev(4, EventKind.TOOL_CALL, "a", "sql_query", sensitivity=3),
        ev(5, EventKind.DATA_ACCESS, "sql_query", "customers_db", op="SELECT", row_volume=50,
           data_classes={"pii"}),
        ev(6, EventKind.TOOL_RESULT, "a", "sql_query", status="ok", trust=Trust.INTERNAL),
    ]


def test_snapshot_collapses_repeats_and_keeps_direction():
    g = SessionGraphs()
    for e in small_session():
        g.add(e)
    snap = g.snapshot("s", T0 + timedelta(seconds=6))
    assert snap.agents == ["p", "a"] and snap.agent_roles == ["planner", "data_analyst"]
    pairs, attrs = snap.edges[("agent", "msg", "agent")]
    assert pairs == [(0, 1)]  # two messages → one edge
    assert attrs[0][0] == pytest.approx(torch.log1p(torch.tensor(2.0)).item())  # with its count
    assert attrs[0][4] == 0.5  # half the messages carried untrusted context
    data = snap.to_hetero()
    for rel in RELATIONS:
        assert torch.equal(data[rev(rel)].edge_index, data[rel].edge_index.flip(0))
    assert data["store"].x.shape == (1, snap.dims["store"])


def test_snapshot_window_and_session_aggregates():
    g = SessionGraphs(session_aggregates=True, window=timedelta(seconds=3))
    for e in small_session():
        g.add(e)
    snap = g.snapshot("s", T0 + timedelta(seconds=7))  # window [4 s, 7 s]: both messages fall outside
    assert snap.dims["agent"] == AGENT_BASE_DIM + SESSION_AGG_DIM
    assert ("agent", "msg", "agent") not in {r for r, (p, _) in snap.edges.items() if p}  # msgs left the window
    assert snap.x["agent"][0][AGENT_BASE_DIM] == 1.0  # session-level: one sensitive store touched
    g.add(ev(7, EventKind.TERMINATE, "p"))
    assert "s" not in g.events  # root terminate drops the session


def test_empty_types_have_right_shape():
    g = SessionGraphs()
    for e in small_session()[:3]:
        g.add(e)
    data = g.snapshot("s", T0 + timedelta(seconds=3)).to_hetero()
    assert data["tool"].x.shape == (0, g.dims["tool"])
    model = HeteroGAE(g.dims)
    z = model.encode(data)
    errs = node_errors(model, data, z)
    assert errs["agent"][0].shape == (2,) and torch.isfinite(errs["agent"][1]).all()


def test_cadence_fires_once_per_stride():
    c = Cadence(timedelta(seconds=10))
    fired = [c.due(ev(i, EventKind.TOOL_CALL, "p", "x", sec=i)) for i in range(0, 31, 2)]
    assert sum(fired) == 3


def test_gae_learns_and_scores():
    events = []
    generate(120, seed=21, extra_sinks=[events.append])
    seqs = collect_snapshots(events, session_aggregates=False)
    assert seqs and all(len(s) >= 1 for s in seqs)
    det = train_gae(seqs[:60], seqs[60:], epochs=3)
    assert det.info.losses[-1] < det.info.losses[0]
    out = det.score(seqs[0][0])
    assert len(out) == len(seqs[0][0].agents)
    assert all(0 < pn <= 1 and 0 < pg <= 1 for _, _, pn, pg in out)
    assert size_bucket(1) == "1-2" and size_bucket(4) == "3-4" and size_bucket(9) == "5+"


def test_recurrent_variant_carries_memory():
    events = []
    generate(60, seed=22, extra_sinks=[events.append])
    seqs = [s for s in collect_snapshots(events, session_aggregates=True) if len(s) >= 2]
    det = train_gae(seqs[:30], seqs[30:], recurrent=True, epochs=2)
    memory: dict = {}
    first = det.agent_scores(seqs[0][0], memory)[0]
    assert set(memory) == set(seqs[0][0].agents)
    again = det.agent_scores(seqs[0][0], memory)[0]  # same snapshot, now with memory
    assert not torch.allclose(first, again)


def test_loss_backprops_through_every_relation():
    events = []
    generate(30, seed=23, extra_sinks=[events.append])
    from torch_geometric.data import Batch
    graphs = [s.to_hetero() for seq in collect_snapshots(events, session_aggregates=False) for s in seq][:16]
    model = HeteroGAE({t: graphs[0][t].x.shape[1] for t in ("agent", "tool", "store")})
    batch = Batch.from_data_list(graphs)
    loss_fn(model, batch, model.encode(batch)).backward()
    assert all(model.W[k].grad is not None for k in model.W)
    assert len(ALL_REL) == 2 * len(RELATIONS)


def test_hybrid_scorer_runs_deep_path_and_attributes_source():
    def evs(n, seed):
        out = []
        generate(n, seed=seed, extra_sinks=[out.append])
        return out
    a, b, c = evs(150, 31), evs(150, 32), evs(150, 33)
    fast = train_fast(a, b, c)
    det = train_gae(collect_snapshots(b, session_aggregates=True), collect_snapshots(c, session_aggregates=True),
                    epochs=2)
    sc = HybridScorer(fast, det, enforce=False)
    generate(40, seed=34, extra_sinks=[sc], attacks={"A5": ATTACKS["A5"]}, attacks_per_type=2)
    assert sc.deep_latency_ms and sc.deep_benign.n > 0
    assert all(src in ("fast", "deep") for *_, src in sc.escalations)
    deep_only = HybridScorer(fast, det, enforce=False, use_fast=False)
    generate(10, seed=35, extra_sinks=[deep_only])
    assert deep_only.benign_stats.n == 0 and deep_only.deep_benign.n > 0

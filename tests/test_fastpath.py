import random
from datetime import datetime, timedelta, timezone

import pytest

from slave.features.fastpath import FEATURES, Baseline, FeatureExtractor
from slave.gateway import Gateway, Policy, ProvenanceRules, ToolOutput
from slave.registry import default_registry
from slave.schema import Event, EventKind, NodeType, Tier
from slave.scoring.calibration import ConformalCalibrator, fuse
from slave.scoring.fastpath import FastPathScorer, train
from slave.scoring.tiers import TierMachine
from slave.sim.attacks import ATTACKS
from slave.sim.swarm import SimClock, generate

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)


def ev(i, kind, src, dst=None, **kw):
    return Event(event_id=f"s:{i:06d}", session_id="s", ts=T0 + timedelta(seconds=i), kind=kind, src_id=src,
                 dst_id=dst, **kw)


def spawn(i, parent, child, role, depth=1):
    return ev(i, EventKind.SPAWN, parent, child, dst_role=role, dst_type=NodeType.AGENT, spawn_depth=depth)


# ---- baseline -----------------------------------------------------------------

def test_surprisal_smoothing_backoff_and_cap():
    b = Baseline(min_context=3)
    for _ in range(10):
        b.observe("coder", "tool:read_file", "tool:write_file", 2)
    b.observe("coder", "tool:read_file", "tool:git_diff", 1)
    common = b.surprisal("coder", "tool:read_file", "tool:write_file")
    rare = b.surprisal("coder", "tool:read_file", "tool:git_diff")
    unseen = b.surprisal("coder", "tool:read_file", "tool:send_email")
    assert common < rare < unseen <= b.surprisal_cap
    # thin role context backs off to the role-agnostic model instead of exploding
    assert b.surprisal("ops", "tool:read_file", "tool:write_file") < unseen
    assert b.role_max_sens["coder"] == 2


def test_baseline_fit_builds_role_tokens():
    events = [spawn(0, "user", "p", "planner", 0), spawn(1, "p", "c", "coder"),
              ev(2, EventKind.MSG_SEND, "p", "c"), ev(3, EventKind.TOOL_CALL, "c", "git_diff", sensitivity=1)]
    b = Baseline().fit(events)
    assert b.trans_role[("planner", "spawn:coder", "msg:coder")] == 1
    assert b.trans_role[("coder", "<start>", "tool:git_diff")] == 1


# ---- features -----------------------------------------------------------------

def test_extractor_vector_and_pingpong():
    fx = FeatureExtractor(Baseline())
    out = [fx.process(e) for e in [spawn(0, "user", "p", "planner", 0), spawn(1, "p", "r", "reviewer")]]
    scored = [s for s in out if s]
    assert len(scored) == 1 and scored[0].agent_id == "p"  # the opener ("user") is not scored
    assert set(scored[0].features) == set(FEATURES)
    last = None
    for i in range(2, 12):
        src, dst = ("p", "r") if i % 2 == 0 else ("r", "p")
        last = fx.process(ev(i, EventKind.MSG_SEND, src, dst)) or last
    assert last.features["pingpong"] > 1.0
    assert last.features["msgs_per_min"] > 1.0


def test_extractor_forgets_session_on_root_terminate():
    fx = FeatureExtractor(Baseline())
    fx.process(spawn(0, "user", "p", "planner", 0))
    fx.process(ev(1, EventKind.TERMINATE, "p"))
    assert "s" not in fx.sessions


# ---- calibration / tiers --------------------------------------------------------

def test_conformal_p_values_are_valid():
    rng = random.Random(0)
    cal = ConformalCalibrator()
    for _ in range(2000):
        cal.add("r", rng.random())
    cal.freeze()
    assert cal.p_value("r", 2.0) == pytest.approx(1 / 2001)
    assert cal.p_value("r", -1.0) == 1.0
    assert cal.p_value("unknown", 5.0) == 1.0  # no data → never alerts
    test = [cal.p_value("r", rng.random()) for _ in range(5000)]
    assert sum(p < 0.05 for p in test) / 5000 < 0.065  # ≈ uniform
    assert fuse([0.01, 0.2]) == pytest.approx(0.02) and fuse([0.9, 0.8]) == 1.0


def test_tier_machine_hysteresis():
    m = TierMachine()
    assert m.update(0.5e-2) == 1
    assert m.update(0.5) == 1 and m.update(0.5) == 1 and m.update(0.5) == 0  # 3 quiet to exit T1
    assert m.update(5e-4) == 2
    assert [m.update(0.5) for _ in range(5)] == [2, 2, 2, 2, 1]
    assert m.update(5e-5) == 2  # one p < 1e-4 is not enough for T3
    assert m.update(5e-5) == 3
    assert m.update(0.9) == 3  # T3 is sticky


def test_controller_only_relaxes_tiers_it_raised():
    reg = default_registry()
    gw = Gateway(reg, policy=Policy(reg, provenance=ProvenanceRules()), executor=lambda t, a: ToolOutput(),
                 clock=SimClock(T0))
    gw.open_session("s", "p", "planner")
    sc = FastPathScorer.__new__(FastPathScorer)  # controller logic only
    sc.enforce, sc.scorer_set = True, {}
    sc.pending = {("s", "p"): (2, 1e-4)}
    sc.controller(gw, "s")
    assert gw.agent_tier("s", "p") is Tier.CONSTRAINED
    sc.pending = {("s", "p"): (1, 0.5)}
    sc.controller(gw, "s")
    assert gw.agent_tier("s", "p") is Tier.ELEVATED
    gw.set_tier("s", "p", Tier.QUARANTINED, "rule")  # a rule escalation…
    sc.pending = {("s", "p"): (0, 0.9)}
    sc.controller(gw, "s")
    assert gw.agent_tier("s", "p") is Tier.QUARANTINED  # …is never relaxed by the scorer


# ---- end to end -----------------------------------------------------------------

@pytest.fixture(scope="module")
def model():
    def events(n, seed):
        out = []
        generate(n, seed=seed, extra_sinks=[out.append], policy=Policy(default_registry()))
        return out
    return train(events(300, 201), events(300, 202), events(300, 203))


def test_fastpath_calibrated_and_detects_loops(model):
    sc = FastPathScorer(model, enforce=False)
    s = generate(150, seed=9, extra_sinks=[sc], attacks={"A5": ATTACKS["A5"]}, attacks_per_type=8)
    st = sc.benign_stats
    assert st.n > 1000
    assert st.below[("fused", 1e-2)] / st.n <= 2e-2  # within 2x nominal
    # tiny calibration sets (≈ hundreds of scores per role) cap how small p can get,
    # so check for Tier 1 flags here; the full-size run is in docs/results/phase3-fastpath.md
    flagged = {sid for sid, _agent, _idx, _p, lvl in sc.alerts if lvl >= 1}
    assert sum(lab.session_id in flagged for lab in s.labels) >= 6


def test_enforcing_scorer_feeds_back_into_gate(model):
    sc = FastPathScorer(model)
    events = []
    generate(0, seed=4, extra_sinks=[sc, events.append], attacks={"A5": ATTACKS["A5"]}, attacks_per_type=3,
             controllers=[sc.controller])
    changes = [e for e in events if e.kind is EventKind.TIER_CHANGE and (e.reason or "").startswith("fast path")]
    assert changes, "scorer should escalate at least one loop agent"

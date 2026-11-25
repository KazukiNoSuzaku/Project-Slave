"""Deep-path detector: snapshot cadence, training, scoring (design.md §6.3, §7).

* Snapshots are taken per session every `STRIDE` of event time (and, in the
  hybrid scorer, immediately when the fast path flags an action).
* Node errors are robust-standardised per node type (median / MAD on part of
  the calibration sessions, a quarter), combined as
  `s(v) = λ·z_attr + (1-λ)·z_struct`, and the graph score is
  `mean(s over agents) + η·top-k mean`.
* Agent node scores get conformal p-values per role; graph scores per
  agent-count bucket (the other three quarters of the calibration sessions). The graph
  p-value is attributed to the top-k agents by node score.
"""

from __future__ import annotations

import random
import statistics
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import torch
from torch_geometric.data import Batch

from slave.graph.gae import HeteroGAE, loss_fn, node_errors
from slave.graph.snapshot import AGENT_BASE_DIM, SessionGraphs, Snapshot
from slave.schema import Event
from slave.scoring.calibration import ConformalCalibrator

# design.md says 30 s; simulated sessions run ~30–80 s of event time (agent
# think times are compressed), so the stride is scaled down to keep several
# snapshots per session.
STRIDE = timedelta(seconds=10)
TOP_K = 3


class Cadence:
    """Fires once per `stride` of event time per session."""

    def __init__(self, stride: timedelta = STRIDE) -> None:
        self.stride = stride
        self.next: dict[str, datetime] = {}

    def due(self, ev: Event) -> bool:
        nxt = self.next.get(ev.session_id)
        if nxt is None:
            self.next[ev.session_id] = ev.ts + self.stride
            return False
        if ev.ts >= nxt:
            self.next[ev.session_id] = ev.ts + self.stride
            return True
        return False

    def fired(self, sid: str, at: datetime) -> None:
        self.next[sid] = at + self.stride


def collect_snapshots(events: Iterable[Event], *, session_aggregates: bool) -> list[list[Snapshot]]:
    """Replay a benign stream into per-session, time-ordered snapshot sequences."""
    graphs = SessionGraphs(session_aggregates=session_aggregates)
    cadence = Cadence()
    out: dict[str, list[Snapshot]] = {}
    for ev in events:
        graphs.add(ev)
        if cadence.due(ev) and (snap := graphs.snapshot(ev.session_id, ev.ts)) is not None:
            out.setdefault(ev.session_id, []).append(snap)
    return list(out.values())


def size_bucket(n_agents: int) -> str:
    return "1-2" if n_agents <= 2 else "3-4" if n_agents <= 4 else "5+"


@dataclass
class _Robust:
    med: float
    mad: float

    def __call__(self, x: torch.Tensor) -> torch.Tensor:
        return (x - self.med) / (1.4826 * self.mad + 1e-6)

    @staticmethod
    def fit(xs: list[float]) -> _Robust:
        med = statistics.median(xs) if xs else 0.0
        mad = statistics.median([abs(x - med) for x in xs]) if xs else 1.0
        return _Robust(med, mad)


@dataclass
class TrainInfo:
    graphs: int
    sessions: int
    epochs: int
    seconds: float
    losses: list[float] = field(default_factory=list)


@dataclass
class GAEDetector:
    model: HeteroGAE
    session_aggregates: bool
    std_attr: _Robust | None = None
    std_struct: _Robust | None = None
    node_cal: ConformalCalibrator = field(default_factory=ConformalCalibrator)
    graph_cal: ConformalCalibrator = field(default_factory=ConformalCalibrator)
    lam: float = 0.5
    eta: float = 1.0
    info: TrainInfo | None = None

    @property
    def recurrent(self) -> bool:
        return self.model.recurrent

    @torch.no_grad()
    def _errors(self, snap: Snapshot, memory: dict[str, torch.Tensor] | None):
        data = snap.to_hetero()
        mem = None
        if self.recurrent:
            memory = memory if memory is not None else {}
            zeros = torch.zeros(self.model.latent)
            mem = torch.stack([memory.get(a, zeros) for a in snap.agents])
        z = self.model.encode(data, mem)
        if self.recurrent and memory is not None:
            for i, a in enumerate(snap.agents):
                memory[a] = z["agent"][i].detach()
        attr, struct = node_errors(self.model, data, z)["agent"]
        return attr, struct

    def agent_scores(self, snap: Snapshot, memory: dict[str, torch.Tensor] | None = None) -> tuple[torch.Tensor, float]:
        attr, struct = self._errors(snap, memory)
        assert self.std_attr is not None and self.std_struct is not None
        s = self.lam * self.std_attr(attr) + (1 - self.lam) * self.std_struct(struct)
        k = min(TOP_K, s.numel())
        g = float(s.mean() + self.eta * s.topk(k).values.mean())
        return s, g

    def score(self, snap: Snapshot, memory: dict[str, torch.Tensor] | None = None) -> list[tuple[str, str, float, float]]:
        """[(agent, role, p_node, p_graph)] — p_graph is 1.0 for agents outside the top-k."""
        s, g = self.agent_scores(snap, memory)
        p_graph = self.graph_cal.p_value(size_bucket(len(snap.agents)), g)
        top = set(s.topk(min(TOP_K, s.numel())).indices.tolist())
        return [(a, role, self.node_cal.p_value(role, float(s[i])), p_graph if i in top else 1.0)
                for i, (a, role) in enumerate(zip(snap.agents, snap.agent_roles))]


def _train_loop(model: HeteroGAE, train: list[list[Snapshot]], *, epochs: int, batch_size: int, lr: float,
                rng: random.Random) -> list[float]:
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    losses = []
    if not model.recurrent:
        graphs = [s.to_hetero() for seq in train for s in seq]
        for _ in range(epochs):
            rng.shuffle(graphs)
            total, n = 0.0, 0
            for i in range(0, len(graphs), batch_size):
                batch = Batch.from_data_list(graphs[i:i + batch_size])
                opt.zero_grad()
                loss = loss_fn(model, batch, model.encode(batch))
                loss.backward()
                opt.step()
                total, n = total + float(loss.detach()), n + 1
            losses.append(total / max(n, 1))
        return losses
    # recurrent: one session per step, back-propagating through its snapshot sequence
    seqs = [[(s.agents, s.to_hetero()) for s in seq] for seq in train]
    for _ in range(epochs):
        rng.shuffle(seqs)
        total, n = 0.0, 0
        for seq in seqs:
            memory: dict[str, torch.Tensor] = {}
            opt.zero_grad()
            loss = torch.zeros(())
            for agents, data in seq:
                mem = torch.stack([memory.get(a, torch.zeros(model.latent)) for a in agents])
                z = model.encode(data, mem)
                loss = loss + loss_fn(model, data, z)
                memory = {a: z["agent"][i] for i, a in enumerate(agents)}
            (loss / len(seq)).backward()
            opt.step()
            total, n = total + float(loss.detach()) / len(seq), n + 1
        losses.append(total / max(n, 1))
    return losses


def train_gae(train: list[list[Snapshot]], cal: list[list[Snapshot]], *, recurrent: bool = False,
              epochs: int = 8, batch_size: int = 32, lr: float = 1e-3, seed: int = 0) -> GAEDetector:
    torch.manual_seed(seed)
    rng = random.Random(seed)
    dims = train[0][0].dims
    model = HeteroGAE(dims, recurrent=recurrent)
    t0 = time.perf_counter()
    model.train()
    losses = _train_loop(model, train, epochs=epochs, batch_size=batch_size, lr=lr, rng=rng)
    model.eval()
    det = GAEDetector(model, session_aggregates=dims["agent"] > AGENT_BASE_DIM)
    det.info = TrainInfo(sum(map(len, train)), len(train), epochs, time.perf_counter() - t0, losses)

    # Conformal p-values bottom out at 1/(n+1), so most calibration sessions go to
    # the conformal sets; a quarter is enough for the median/MAD standardiser.
    split = len(cal) // 4
    attr_all, struct_all = [], []
    for seq in cal[:split]:
        memory: dict[str, torch.Tensor] = {}
        for snap in seq:
            a, s = det._errors(snap, memory)
            attr_all += a.tolist()
            struct_all += s.tolist()
    det.std_attr, det.std_struct = _Robust.fit(attr_all), _Robust.fit(struct_all)
    for seq in cal[split:]:
        memory = {}
        for snap in seq:
            s, g = det.agent_scores(snap, memory)
            for role, v in zip(snap.agent_roles, s.tolist()):
                det.node_cal.add(role, v)
            det.graph_cal.add(size_bucket(len(snap.agents)), g)
    det.node_cal.freeze()
    det.graph_cal.freeze()
    return det

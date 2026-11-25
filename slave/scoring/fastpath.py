"""Fast-path model and scorer (design.md §5, §7).

`FastPathModel` bundles everything learned from benign traffic:

1. `Baseline` — transition / action statistics (training split A),
2. per-feature min/max scaling and one River `HalfSpaceTrees` per role
   (training split B),
3. a `ConformalCalibrator` per detector (calibration split).

Two detectors are calibrated and fused: the HST anomaly score and the raw
transition surprisal. `FastPathScorer` runs the model online as a gateway sink;
tier changes it decides are applied by its controller *after* the current
action, so the gate enforces them from the agent's next action on.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from river.anomaly import HalfSpaceTrees

from slave.features.fastpath import FEATURES, Baseline, FeatureExtractor, Scored
from slave.gateway import Gateway
from slave.schema import Event, Tier
from slave.scoring.calibration import ConformalCalibrator, fuse
from slave.scoring.tiers import Thresholds, TierMachine

DETECTORS = ("hst", "transition")


@dataclass
class Scaler:
    lo: dict[str, float] = field(default_factory=dict)
    hi: dict[str, float] = field(default_factory=dict)

    def fit(self, rows: Iterable[dict[str, float]]) -> Scaler:
        for row in rows:
            for k, v in row.items():
                self.lo[k] = min(self.lo.get(k, v), v)
                self.hi[k] = max(self.hi.get(k, v), v)
        return self

    def __call__(self, row: dict[str, float]) -> dict[str, float]:
        # values beyond the benign range clip to the edge: HST expects [0, 1]
        out = {}
        for k in FEATURES:
            lo, hi = self.lo.get(k, 0.0), self.hi.get(k, 0.0)
            out[k] = 0.0 if hi <= lo else min(1.0, max(0.0, (row[k] - lo) / (hi - lo)))
        return out


@dataclass
class FastPathModel:
    baseline: Baseline
    scaler: Scaler
    hst: dict[str, HalfSpaceTrees]
    calibrators: dict[str, ConformalCalibrator]

    def raw_scores(self, s: Scored) -> dict[str, float]:
        model = self.hst.get(s.role)
        hst = model.score_one(self.scaler(s.features)) if model else 0.0
        return {"hst": hst, "transition": s.features["trans_surprisal"]}

    def p_values(self, s: Scored) -> dict[str, float]:
        raw = self.raw_scores(s)
        return {d: self.calibrators[d].p_value(s.role, raw[d]) for d in DETECTORS}


# ---- training -----------------------------------------------------------------

def _scored(baseline: Baseline, events: Iterable[Event]) -> list[Scored]:
    fx = FeatureExtractor(baseline)
    return [s for ev in events if (s := fx.process(ev)) is not None]


def train(events_a: Iterable[Event], events_b: Iterable[Event], events_cal: Iterable[Event], *,
          n_trees: int = 25, height: int = 8, window: int = 250, seed: int = 0) -> FastPathModel:
    """Fit on three disjoint benign event streams (A: baseline, B: HST, cal: calibration)."""
    baseline = Baseline().fit(events_a)

    rows_b = _scored(baseline, events_b)
    scaler = Scaler().fit(s.features for s in rows_b)
    hst: dict[str, HalfSpaceTrees] = {}
    for s in rows_b:
        if s.role not in hst:
            hst[s.role] = HalfSpaceTrees(n_trees=n_trees, height=height, window_size=window, seed=seed)
        hst[s.role].learn_one(scaler(s.features))

    model = FastPathModel(baseline, scaler, hst, {d: ConformalCalibrator() for d in DETECTORS})
    for s in _scored(baseline, events_cal):
        for d, v in model.raw_scores(s).items():
            model.calibrators[d].add(s.role, v)
    for c in model.calibrators.values():
        c.freeze()
    return model


# ---- online scorer ------------------------------------------------------------

@dataclass
class ScoreStats:
    """Counts for checking calibration on benign traffic (sessions not prefixed 'atk-')."""

    n: int = 0
    below: Counter = field(default_factory=Counter)  # (detector, alpha) -> count

    ALPHAS = (1e-2, 1e-3, 1e-4)

    def add(self, ps: dict[str, float]) -> None:
        self.n += 1
        for d, p in ps.items():
            for a in self.ALPHAS:
                if p < a:
                    self.below[(d, a)] += 1


class FastPathScorer:
    """Gateway sink + controller. `enforce=False` scores without changing tiers."""

    def __init__(self, model: FastPathModel, *, enforce: bool = True, thresholds: Thresholds = Thresholds()):
        self.model = model
        self.enforce = enforce
        self.thresholds = thresholds
        self.fx = FeatureExtractor(model.baseline)
        # One tier machine per (agent, detector family): each family keeps its own
        # streaks and quiet counts; the agent's tier is the max across families.
        self.machines: dict[tuple[str, str], dict[str, TierMachine]] = {}
        self.levels: dict[tuple[str, str], int] = {}
        self.pending: dict[tuple[str, str], tuple[int, float, str]] = {}
        self.scorer_set: dict[tuple[str, str], int] = {}
        self.benign_stats = ScoreStats()
        self.alerts: list[tuple[str, str, int, float, int, str]] = []  # (session, agent, idx, p*, level, source)
        # tier *increases* only, attributed to the scorer whose p* caused them
        self.escalations: list[tuple[str, str, int, float, int, str]] = []

    def __call__(self, ev: Event) -> None:
        self.score_event(ev)

    def score_event(self, ev: Event) -> float | None:
        """Score one event on the fast path; returns p* for scored actions."""
        s = self.fx.process(ev)
        if s is None:
            return None
        ps = self.model.p_values(s)
        p_star = fuse(list(ps.values()))
        if not s.session_id.startswith("atk-"):
            self.benign_stats.add(ps | {"fused": p_star})
        self.update_tier(s.session_id, s.agent_id, s.idx, p_star)
        return p_star

    def update_tier(self, session_id: str, agent_id: str, idx: int, p_star: float, source: str = "fast") -> None:
        key = (session_id, agent_id)
        families = self.machines.setdefault(key, {})
        families.setdefault(source, TierMachine(self.thresholds)).update(p_star)
        before = self.levels.get(key, 0)
        level = max(m.level for m in families.values())
        self.levels[key] = level
        if level != before:
            self.pending[key] = (level, p_star, source)
        if level > before:
            self.escalations.append((session_id, agent_id, idx, p_star, level, source))
        if level >= 1:
            self.alerts.append((session_id, agent_id, idx, p_star, level, source))

    def controller(self, gw: Gateway, session_id: str) -> None:
        if not self.enforce or not self.pending:
            return
        for key in [k for k in self.pending if k[0] == session_id]:
            level, p_star, source = self.pending.pop(key)
            current = gw.agent_tier(*key)
            if current is None:
                continue
            reason = f"{source} path p*={p_star:.1e}"
            if level > current:
                gw.set_tier(*key, Tier(level), reason)
                self.scorer_set[key] = level
            elif level < current and self.scorer_set.get(key) == current:
                # only relax tiers the scorer itself raised; rule-based escalations stay
                gw.set_tier(*key, Tier(level), reason + " (hysteresis exit)")
                self.scorer_set[key] = level

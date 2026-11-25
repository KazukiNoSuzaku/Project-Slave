"""Fast path + deep path in one scorer (design.md §2, §7).

The fast path scores every action. The deep path (graph autoencoder) scores a
session snapshot every `STRIDE` of event time, and immediately whenever the
fast path flags an action (p* < `trigger_p`). Calibration is checked on the
regular (cadence) snapshots only. Triggered snapshots are taken at moments
already selected as unusual, so they are not exchangeable with the calibration
set. Their benign rates are reported separately. Each scoring moment fuses only
the p-values that are *fresh* at that moment:

* action moments: HST + transition (as in Phase 3),
* snapshot moments: GAE node + GAE graph (graph p only for the top-k agents),

each with Bonferroni over its own detectors. Each family drives its own tier
machine per agent and the agent's tier is the max of the two. With one shared
machine, a routine snapshot landing between two alarming actions would reset
the fast path's "two consecutive" Tier 3 streak, and routine scores from one
family would count as quiet time for the other. Reusing a stale p-value at a
later moment would let one extreme score count twice.
"""

from __future__ import annotations

import time

import torch

from slave.graph.detector import Cadence, GAEDetector
from slave.graph.snapshot import SessionGraphs
from slave.schema import Event, EventKind
from slave.scoring.calibration import fuse
from slave.scoring.fastpath import FastPathModel, FastPathScorer, ScoreStats
from slave.scoring.tiers import Thresholds


class HybridScorer(FastPathScorer):
    def __init__(self, fast: FastPathModel, deep: GAEDetector, *, enforce: bool = True,
                 thresholds: Thresholds = Thresholds(), trigger_p: float = 1e-2, use_fast: bool = True) -> None:
        """`use_fast=False`: deep path alone (cadence snapshots only), for ablation."""
        super().__init__(fast, enforce=enforce, thresholds=thresholds)
        self.deep = deep
        self.use_fast = use_fast
        self.trigger_p = trigger_p
        self.graphs = SessionGraphs(session_aggregates=deep.session_aggregates)
        self.cadence = Cadence()
        self.memory: dict[str, dict[str, torch.Tensor]] = {}
        self.deep_benign = ScoreStats()  # cadence snapshots only (exchangeable with calibration)
        self.deep_triggered_benign = ScoreStats()  # snapshots forced by a fast-path flag
        self.deep_latency_ms: list[float] = []

    def __call__(self, ev: Event) -> None:
        p_fast = self.score_event(ev) if self.use_fast else None
        self.graphs.add(ev)
        sid = ev.session_id
        if sid not in self.graphs.roles:  # session closed (root terminated)
            self.memory.pop(sid, None)
            self.cadence.next.pop(sid, None)
            return
        due = self.cadence.due(ev)
        triggered = p_fast is not None and p_fast < self.trigger_p
        if (due or triggered) and ev.kind is not EventKind.TERMINATE:
            self.cadence.fired(sid, ev.ts)
            self._deep(ev, triggered=triggered and not due)

    def _deep(self, ev: Event, *, triggered: bool) -> None:
        sid = ev.session_id
        t0 = time.perf_counter()
        snap = self.graphs.snapshot(sid, ev.ts)
        if snap is None:
            return
        results = self.deep.score(snap, self.memory.setdefault(sid, {}))
        self.deep_latency_ms.append((time.perf_counter() - t0) * 1000)
        idx = int(ev.event_id.rsplit(":", 1)[1])
        stats = None if sid.startswith("atk-") else self.deep_triggered_benign if triggered else self.deep_benign
        for agent, _role, p_node, p_graph in results:
            ps = {"gae_node": p_node, "gae_graph": p_graph}
            p_star = fuse(list(ps.values()))
            if stats is not None:
                stats.add(ps | {"fused": p_star})
            self.update_tier(sid, agent, idx, p_star, source="deep")

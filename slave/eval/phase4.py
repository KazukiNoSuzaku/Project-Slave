"""Phase 4 evaluation: the graph-autoencoder deep path (design.md §6, §11 rungs 4–6).

Training data comes from the same three benign splits as Phase 3:
split A fits the fast-path transition baseline, split B trains the HST *and*
the GAE, split C calibrates both (for the GAE: a quarter for standardisation,
three quarters for conformal p-values).

| Rung | Scorer |
|------|--------|
| R3 | gate (R2) + fast path |
| R4 | R3 + GAE v1 (static windowed snapshots) |
| R5 | R3 + GAE v2a (v1 + whole-session aggregates on agent nodes) |
| R6 | R3 + GAE v2b (v2a + per-agent GRU memory across snapshots) |
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass

from slave.eval.phase2 import RUNGS as GATE_RUNGS, Rung, RungResult, _pct, render as render_gate_tables, run_rung
from slave.eval.phase3 import TRAIN_SEEDS, _benign_events
from slave.graph.detector import GAEDetector, collect_snapshots, train_gae
from slave.scoring.fastpath import FastPathModel, FastPathScorer, ScoreStats, train
from slave.scoring.hybrid import HybridScorer

VARIANTS = {
    "v1": dict(session_aggregates=False, recurrent=False),
    "v2a": dict(session_aggregates=True, recurrent=False),
    "v2b": dict(session_aggregates=True, recurrent=True),
}
RUNG_FOR = {"v1": "R4", "v2a": "R5", "v2b": "R6"}
DEEP_ONLY = "v2a"  # variant also run without the fast path


@dataclass
class Phase4Result:
    fast: FastPathModel
    detectors: dict[str, GAEDetector]
    train_s: float
    n_train: int
    gae_sessions: int
    results: list[RungResult]


def run(seeds: list[int], n_benign: int, n_attacks: int, n_train: int, gae_sessions: int, epochs: int,
        variants: list[str], log=print) -> Phase4Result:
    t0 = time.perf_counter()
    a, b, c = (_benign_events(n_train, s) for s in TRAIN_SEEDS)
    fast = train(a, b, c)
    log(f"fast path trained ({time.perf_counter() - t0:.0f}s)")
    detectors = {}
    for v in variants:
        cfg = VARIANTS[v]
        tr = collect_snapshots(b, session_aggregates=cfg["session_aggregates"])[:gae_sessions]
        cal = collect_snapshots(c, session_aggregates=cfg["session_aggregates"])
        ep = max(2, epochs // 2) if cfg["recurrent"] else epochs  # v2b takes one step per session
        detectors[v] = train_gae(tr, cal, recurrent=cfg["recurrent"], epochs=ep)
        info = detectors[v].info
        log(f"GAE {v}: {info.graphs:,} graphs, {ep} epochs, loss {info.losses[0]:.3f}→{info.losses[-1]:.3f} "
            f"({info.seconds:.0f}s)")
    train_s = time.perf_counter() - t0

    base = {r.key: r for r in GATE_RUNGS}["R2"]
    results = [run_rung(Rung("R3", "R2 + fast path", base.provenance, base.config), seeds, n_benign, n_attacks,
                        make_scorer=lambda: FastPathScorer(fast))]
    log("R3 done")
    if DEEP_ONLY in detectors:
        det = detectors[DEEP_ONLY]
        rung = Rung("R2+G", f"R2 + GAE {DEEP_ONLY} alone (no fast path)", base.provenance, base.config)
        results.append(run_rung(rung, seeds, n_benign, n_attacks,
                                make_scorer=lambda: HybridScorer(fast, det, use_fast=False)))
        log(f"{rung.key} done")
    for v in variants:
        det = detectors[v]
        rung = Rung(RUNG_FOR[v], f"R3 + GAE {v}", base.provenance, base.config)
        results.append(run_rung(rung, seeds, n_benign, n_attacks, make_scorer=lambda d=det: HybridScorer(fast, d)))
        log(f"{rung.key} done")
    return Phase4Result(fast, detectors, train_s, n_train, gae_sessions, results)


def _has_deep(r: RungResult) -> bool:
    return bool(r.scorers) and hasattr(r.scorers[0], "deep")


def _deep_contrib(r: RungResult, attack: str) -> tuple[int, int, int]:
    alerts: dict[str, list] = {}
    for sc in r.scorers:
        for a in sc.escalations:
            alerts.setdefault(a[0], []).append(a)
    any_n = first_n = n = 0
    for lab in r.labels:
        if lab.attack != attack:
            continue
        n += 1
        if lab.first_malicious_idx is None:
            continue
        # escalations into Tier >= 2; list order is the order they happened (ties at one index included)
        hits = [(idx, src) for sid, agent, idx, _p, lvl, src in alerts.get(lab.session_id, [])
                if agent in lab.attackers and lvl >= 2 and idx >= lab.first_malicious_idx]
        if any(src == "deep" for _, src in hits):
            any_n += 1
            first_n += hits[0][1] == "deep"
    return any_n, first_n, n


def _merged(scorers, attr: str) -> ScoreStats:
    out = ScoreStats()
    for s in scorers:
        st = getattr(s, attr)
        out.n += st.n
        out.below.update(st.below)
    return out


def _cal_rows(key: str, stats: ScoreStats, detectors: list[str]) -> tuple[list[str], bool]:
    rows, ok = [], True
    for d in detectors:
        cells = []
        for a in ScoreStats.ALPHAS:
            rate = stats.below[(d, a)] / max(stats.n, 1)
            passed = rate <= 2 * a
            ok &= passed
            cells.append(f"{100 * rate:.3f}% {'✓' if passed else '✗'}")
        rows.append(f"| {key} | {d} | {stats.n:,} | " + " | ".join(cells) + " |")
    return rows, ok


def render(res: Phase4Result, seeds: list[int], n_benign: int, n_attacks: int) -> str:
    body = render_gate_tables(res.results, seeds, n_benign, n_attacks).split("\n## Reading these numbers")[0]
    body = body.replace("# Phase 2 results: gate-rule ablation", "# Phase 4 results: graph-autoencoder deep path")
    body = body.replace("`uv run slave-eval phase2` (see `slave/eval/phase2.py`)",
                        "`uv run slave-eval phase4` (see `slave/eval/phase4.py`)")
    lines = ["## Models", "",
             f"Fast path as in Phase 3, trained on {3 * res.n_train:,} benign sessions. Each GAE variant trains on the "
             f"snapshots of {res.gae_sessions:,} sessions from split B and is calibrated on split C. Training time in "
             f"total: {res.train_s:.0f}s.", "",
             "| Variant | Graphs | Epochs | Loss first → last | Train time | Node-score calibration n per role |",
             "|---|---|---|---|---|---|"]
    for v, det in res.detectors.items():
        i = det.info
        cal = ", ".join(f"{r} {len(xs):,}" for r, xs in sorted(det.node_cal.scores.items()))
        lines.append(f"| {v} | {i.graphs:,} | {i.epochs} | {i.losses[0]:.3f} → {i.losses[-1]:.3f} | {i.seconds:.0f}s | {cal} |")

    lines += ["", "## Calibration on held-out benign traffic (empirical ≤ 2× nominal)", "",
              "| Rung | Detector | Scorings | " + " | ".join(f"p < {a:g}" for a in ScoreStats.ALPHAS) + " |",
              "|---|---|---|" + "---|" * len(ScoreStats.ALPHAS)]
    ok = True
    for r in res.results:
        rows, good = _cal_rows(r.rung.key, _merged(r.scorers, "benign_stats"), ["fused"])
        lines += [x.replace("| fused |", "| fast path fused |") for x in rows]
        ok &= good
        if hasattr(r.scorers[0], "deep_benign"):
            rows, good = _cal_rows(r.rung.key, _merged(r.scorers, "deep_benign"), ["gae_node", "gae_graph", "fused"])
            lines += [x.replace("| fused |", "| deep path fused (cadence) |") for x in rows]
            ok &= good
            rows, _ = _cal_rows(r.rung.key, _merged(r.scorers, "deep_triggered_benign"), ["fused"])
            lines += [x.replace("| fused |", "| deep path fused (triggered, not exchangeable) |").replace(" ✓", "").replace(" ✗", "")
                      for x in rows]
    lines += ["", f"**Calibration {'holds' if ok else 'does NOT hold'} for every exchangeable detector and rung.** "
              "Triggered snapshots are taken right after the fast path flags an action. Their benign rates show how "
              "often the deep path *corroborates* a fast-path false positive. They are not a calibration test.", ""]

    lines += ["## What the deep path contributes on attacks", "",
              "Share of attack sessions where a GAE p-value *caused* an attacker agent's tier to rise to ≥2 at or "
              "after the attack's first malicious event, and where that was the first such escalation.", "",
              "| Attack | " + " | ".join(f"{r.rung.key}: any / first" for r in res.results if _has_deep(r)) + " |",
              "|---|" + "---|" * sum(_has_deep(r) for r in res.results)]
    from slave.sim.attacks import ATTACKS
    for name in ATTACKS:
        cells = []
        for r in res.results:
            if not _has_deep(r):
                continue
            any_n, first_n, n = _deep_contrib(r, name)
            cells.append(f"{100 * any_n / max(n, 1):.0f}% / {100 * first_n / max(n, 1):.0f}%")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    lines += [""]

    lines += ["## Deep-path latency (snapshot build + GAE inference + scoring)", "",
              "| Rung | Snapshots scored | p50 | p99 | Budget |", "|---|---|---|---|---|"]
    for r in res.results:
        lat = [x for s in r.scorers for x in getattr(s, "deep_latency_ms", [])]
        if lat:
            lat.sort()
            p99 = lat[min(len(lat) - 1, int(0.99 * len(lat)))]
            lines.append(f"| {r.rung.key} | {len(lat):,} | {statistics.median(lat):.1f} ms | {p99:.1f} ms | "
                         f"{'✓' if p99 <= 150 else '✗'} ≤150 ms |")

    lines += ["", "## Benign sessions by highest tier reached", "",
              "| Rung | Benign sessions | Tier ≥1 | Tier ≥2 | Tier 3 |", "|---|---|---|---|---|"]
    for r in res.results:
        n = r.benign_sessions
        ge = lambda t: sum(v for k, v in r.benign_max_tier.items() if k >= t)  # noqa: E731
        lines.append(f"| {r.rung.key} | {n:,} | {_pct(ge(1), n, 2)} | {_pct(ge(2), n, 2)} | {_pct(ge(3), n, 2)} |")
    lines += ["", NOTES]
    return body + "\n" + "\n".join(lines)


NOTES = """## Reading these numbers

- **Each scoring moment fuses only fresh p-values.** At an action, the score combines the HST and transition detectors. At a snapshot, it combines the GAE node and graph scores. Each family has its own tier machine per agent, and the agent's tier is the higher of the two, so neither family can reset the other's streaks. The deep path still adds scoring moments, and the benign tier table shows what that costs.
- **The deep path is slower to react by design.** It runs every 10 s of session time (scaled down from the design's 30 s because simulated sessions are short), or immediately when the fast path flags an action. An attack that completes inside one stride, without tripping the fast path, is invisible to it.
- **v2b trains with back-propagation through each session's snapshots,** one session per step and for half as many epochs as v1/v2a, because GRU memory doesn't batch across sessions. Sessions are short (a handful of snapshots), so the memory has little history to use except in A6 (slow burn).
- **Attack, over-taint and simulator caveats from Phases 2–3 still apply.**
"""

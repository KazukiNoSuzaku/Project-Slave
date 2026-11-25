"""Phase 3 evaluation: the behavioural fast path (design.md §5, §7, §11 rung 3).

1. Train the fast-path model on three disjoint benign streams
   (A: transition baseline, B: Half-Space Trees, C: conformal calibration).
2. Run held-out test seeds (benign + every attack, randomised variants) for
   gate-only rungs and for the same rungs plus the enforcing fast path.
3. Check calibration: on benign test traffic, the share of scored actions with
   p < α must stay within 2× of α (Phase 3 exit criterion).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from slave.eval.phase2 import (
    RUNGS as GATE_RUNGS,
    RungResult,
    _pct,
    render as render_gate_tables,
    run_rung,
)
from slave.gateway import Policy
from slave.registry import default_registry
from slave.scoring.fastpath import DETECTORS, FastPathModel, FastPathScorer, ScoreStats, train
from slave.sim.swarm import generate

TRAIN_SEEDS = (101, 102, 103)


def _benign_events(n: int, seed: int) -> list:
    events: list = []
    generate(n, seed=seed, extra_sinks=[events.append], policy=Policy(default_registry()))
    return events


def train_model(n_per_split: int) -> tuple[FastPathModel, float]:
    t0 = time.perf_counter()
    a, b, c = (_benign_events(n_per_split, s) for s in TRAIN_SEEDS)
    return train(a, b, c), time.perf_counter() - t0


@dataclass
class Phase3Result:
    model: FastPathModel
    train_s: float
    n_train: int
    results: list[RungResult]


def run(seeds: list[int], n_benign: int, n_attacks: int, n_train: int) -> Phase3Result:
    model, train_s = train_model(n_train)
    gate = {r.key: r for r in GATE_RUNGS}
    results = []
    for key in ("R2", "R2-reset"):
        results.append(run_rung(gate[key], seeds, n_benign, n_attacks))
    for key in ("R2", "R2-reset"):
        base = gate[key]
        rung = type(base)(key.replace("R2", "R3"), f"{key} + fast path (HST + transition, enforcing)",
                          base.provenance, base.config)
        results.append(run_rung(rung, seeds, n_benign, n_attacks, make_scorer=lambda: FastPathScorer(model)))
    return Phase3Result(model, train_s, n_train, results)


def _calibration_table(results: list[RungResult]) -> list[str]:
    lines = ["## Calibration on held-out benign traffic (exit criterion: empirical ≤ 2× nominal)", "",
             "| Rung | Detector | Scored actions | " + " | ".join(f"p < {a:g}" for a in ScoreStats.ALPHAS) + " |",
             "|---|---|---|" + "---|" * len(ScoreStats.ALPHAS)]
    ok = True
    for r in results:
        if not r.scorers:
            continue
        stats = ScoreStats()
        for s in r.scorers:
            stats.n += s.benign_stats.n
            stats.below.update(s.benign_stats.below)
        for d in (*DETECTORS, "fused"):
            cells = []
            for a in ScoreStats.ALPHAS:
                rate = stats.below[(d, a)] / max(stats.n, 1)
                passed = rate <= 2 * a
                ok &= passed
                cells.append(f"{100 * rate:.3f}% {'✓' if passed else '✗'}")
            lines.append(f"| {r.rung.key} | {d} | {stats.n:,} | " + " | ".join(cells) + " |")
    lines += ["", f"**Exit criterion {'met' if ok else 'NOT met'}.** Nominal rates are 1%, 0.1% and 0.01%. "
              "The fused score is Bonferroni-adjusted, so it should come in at or below nominal.", ""]
    return lines


def _tier_cost_table(results: list[RungResult]) -> list[str]:
    lines = ["## Benign sessions by highest tier reached", "",
             "| Rung | Benign sessions | Tier ≥1 | Tier ≥2 | Tier 3 |", "|---|---|---|---|---|"]
    for r in results:
        n = r.benign_sessions
        ge = lambda t: sum(v for k, v in r.benign_max_tier.items() if k >= t)  # noqa: E731
        lines.append(f"| {r.rung.key} | {n:,} | {_pct(ge(1), n, 2)} | {_pct(ge(2), n, 2)} | {_pct(ge(3), n, 2)} |")
    lines.append("")
    return lines


def render(res: Phase3Result, seeds: list[int], n_benign: int, n_attacks: int) -> str:
    gate_tables = render_gate_tables(res.results, seeds, n_benign, n_attacks)
    body = gate_tables.split("\n## Reading these numbers")[0]
    body = body.replace("# Phase 2 results: gate-rule ablation", "# Phase 3 results: behavioural fast path")
    body = body.replace("`uv run slave-eval phase2` (see `slave/eval/phase2.py`)",
                        "`uv run slave-eval phase3` (see `slave/eval/phase3.py`)")
    cal = res.model.calibrators["hst"]
    roles = sorted(res.model.hst)
    sizes = ", ".join(f"{r} {cal.n(r):,} (min p {1 / (cal.n(r) + 1):.0e})" for r in roles)
    extra = [
        "## Model",
        "",
        f"Trained on {3 * res.n_train:,} benign sessions (seeds {TRAIN_SEEDS}; {res.n_train:,} each for the transition "
        f"baseline, the Half-Space Trees and calibration) in {res.train_s:.0f}s. "
        "There is one HST per role (25 trees, height 8) over 19 features. Two detectors are calibrated per role: the HST score "
        "and the transition surprisal. They are fused as p* = min(1, 2·min p).",
        "",
        f"Calibration scores per role: {sizes}. "
        "The fused p* is at least 2/(n+1), so a role needs more than about 20,000 calibration scores before the fast path alone can push it to Tier 3 (p* < 1e-4).",
        "",
        *_calibration_table(res.results),
        *_tier_cost_table(res.results),
        PHASE3_NOTES,
    ]
    return body + "\n" + "\n".join(extra)


PHASE3_NOTES = """## Reading these numbers

- **Detection is not prevention.** The fast path scores an action *after* the gate has decided on it. Its tier change applies from the agent's next action. A single harmful action is caught by the fast path only if earlier actions already looked anomalous enough to reach Tier 2. Tier 2 blocks changing data, sending data out and spawning, but not messages. Only Tier 3 stops messages, which is why A5 needs two consecutive p* < 1e-4.
- **The score uses provenance features.** "Untrusted" and "holds PII" are features, so the fast path partly re-learns the provenance signal statistically. That is how it reaches attacks such as A7 that slip under the rule thresholds.
- **Attacks are randomised but simulated.** Lengths, targets, cover actions and ordering vary per instance, but the attack families are fixed and known when the system is designed. Adaptive attackers who tune themselves against these features are out of scope here.
- **Some catches rely on one signature.** A3, A6 and A8 are mostly stopped *before* they start, because the planner spawns several agents in a burst and gets constrained ("aborted before harm" above). An attacker who spreads the spawns out would fall back to the gate rules (P2/P3), which still prevent all three.
- **Detection is only counted from the attack's first malicious event onwards.** Earlier flags on the same agents count as false positives, not as detections.
- **Over-taint numbers carry the same lower-bound caveat as Phase 2.**
"""

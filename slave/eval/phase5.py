"""Phase 5 evaluation: enforcement and quarantine semantics (design.md §8, §13 Phase 5).

Part A: chaos test (no detectors). Benign sessions run with a chaos monkey that
quarantines a random non-root agent mid-session. Exit criterion: **zero benign
sibling hangs**, i.e. no live agent left waiting on a report that will never
come. The same run with parent notices switched off is the negative control:
it shows the test can fail. A second variant quarantines the root to exercise
the session freeze.

Part B: full stack. Gate (R2) + fast path + GAE v2a, with a simulated human
reviewer who releases quarantines in benign sessions and confirms the ones in
attack sessions (running reversible compensations). Exit criterion: **Tier 3
enforced ≤100 ms after the scorer decides**, measured on the wall clock. Also
reported: A8 freezes, compensation coverage of executed harm, and what happens
after a release.
"""

from __future__ import annotations

import random
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from slave.eval.phase3 import TRAIN_SEEDS, _benign_events
from slave.eval.phase2 import _pct
from slave.gateway import Gateway, Policy, ProvenanceRules
from slave.graph.detector import collect_snapshots, train_gae
from slave.registry import default_registry
from slave.schema import Event, EventKind, Tier
from slave.scoring.fastpath import train
from slave.scoring.hybrid import HybridScorer
from slave.sim.attacks import ATTACKS
from slave.sim.swarm import generate

ENFORCEMENT_RULES = {"T2", "T3", "TERMINATED", "FROZEN"}
# Denials an agent suffers because *another* agent was quarantined. T2/T3 on an
# agent are decisions about that agent itself, and are reported separately.
COLLATERAL_RULES = {"TERMINATED", "FROZEN"}
QUARANTINE_BUDGET_MS = 100.0


def _policy() -> Policy:
    return Policy(default_registry(), provenance=ProvenanceRules())


def _idx(ev: Event) -> int:
    return int(ev.event_id.rsplit(":", 1)[1])


class Denials:
    """Sink: gate denials and enforcement events per session."""

    def __init__(self) -> None:
        self.denials: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
        self.allowed_after: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self.releases: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self.frozen: set[str] = set()

    def __call__(self, ev: Event) -> None:
        if ev.kind is EventKind.GATE_DECISION:
            if ev.decision != "allow":
                self.denials[ev.session_id].append((_idx(ev), ev.src_id, ev.rule or "?"))
            else:
                self.allowed_after[ev.session_id].append((_idx(ev), ev.src_id))
        elif ev.kind is EventKind.TIER_CHANGE and (ev.reason or "").startswith("released"):
            self.releases[ev.session_id].append((_idx(ev), ev.src_id))
        elif ev.kind is EventKind.NOTICE and ev.dst_id == "human":
            self.frozen.add(ev.session_id)


# ---- Part A: chaos ------------------------------------------------------------

class Chaos:
    """Controller: quarantines one random agent in a share of sessions."""

    def __init__(self, rate: float, seed: int, *, root: bool = False) -> None:
        self.rate, self.root = rate, root
        self.rng = random.Random(seed)
        self.plan: dict[str, int | None] = {}
        self.hits: dict[str, tuple[str, int]] = {}  # session → (agent, event index)

    def __call__(self, gw: Gateway, sid: str) -> None:
        if sid not in self.plan:
            self.plan[sid] = self.rng.randint(4, 30) if self.rng.random() < self.rate else None
        at = self.plan[sid]
        if at is None or gw.event_count(sid) < at or sid not in gw.sessions:
            return
        sess = gw.sessions[sid]
        cands = sorted(a.agent_id for a in sess.agents.values()
                       if (a.parent_id is None) == self.root and not a.terminated and a.tier < Tier.QUARANTINED)
        if not cands:
            return  # try again after the next action
        self.plan[sid] = None
        target = self.rng.choice(cands)
        self.hits[sid] = (target, gw.event_count(sid))
        gw.set_tier(sid, target, Tier.QUARANTINED, "chaos test")


@dataclass
class ChaosResult:
    name: str
    sessions: int = 0
    quarantines: int = 0
    runtime: Counter = field(default_factory=Counter)
    collateral: int = 0  # enforcement denials on agents outside the quarantined scope
    collateral_sessions: int = 0
    frozen: int = 0
    notices: int = 0
    open_sessions_left: int = 0


def run_chaos(name: str, seeds: list[int], n: int, *, rate: float, notify: bool, root: bool = False) -> ChaosResult:
    out = ChaosResult(name)
    for seed in seeds:
        chaos, den = Chaos(rate, seed + 1000, root=root), Denials()
        s = generate(n, seed=seed, policy=_policy(), extra_sinks=[den], controllers=[chaos], notify_parent=notify)
        gw = s.gateway
        out.sessions += s.sessions
        out.quarantines += len(chaos.hits)
        out.runtime.update(s.runtime)
        out.frozen += len(den.frozen)
        out.notices += sum(len(v) for v in gw.enforcer.inbox.values())
        out.open_sessions_left += len(gw.sessions)
        scope: dict[str, set[str]] = defaultdict(set)
        for inc in gw.enforcer.incidents.values():
            scope[inc.session_id] |= {inc.agent_id, *inc.subtree}
        for sid, (_agent, at) in chaos.hits.items():
            if sid in den.frozen:
                continue  # freezing everyone is the intended behaviour there
            bad = [d for d in den.denials.get(sid, []) if d[0] >= at and d[2] in COLLATERAL_RULES
                   and d[1] not in scope[sid]]
            out.collateral += len(bad)
            out.collateral_sessions += bool(bad)
    return out


# ---- Part B: full stack ---------------------------------------------------------

class Reviewer:
    """Controller: a simulated on-call human. Benign session → release; attack → confirm + compensate."""

    def __init__(self, gw_ref: list, delay: int = 5) -> None:
        self.delay = delay
        self.gw_ref = gw_ref
        self.seen = 0
        self.queue: list[tuple[str, int]] = []  # (incident id, event index when noticed)
        self.stats: Counter = Counter()

    def _poll(self, gw: Gateway) -> None:
        incs = list(gw.enforcer.incidents.values())
        for inc in incs[self.seen:]:
            self.queue.append((inc.id, gw.event_count(inc.session_id)))
        self.seen = len(incs)

    def __call__(self, gw: Gateway, sid: str) -> None:
        self.gw_ref[:] = [gw]
        self._poll(gw)
        keep = []
        for inc_id, at in self.queue:
            inc = gw.enforcer.incidents[inc_id]
            if inc.session_id != sid or gw.event_count(sid) - at < self.delay:
                keep.append((inc_id, at))
                continue
            self._decide(gw, inc)
        self.queue = keep

    def _decide(self, gw: Gateway, inc) -> None:
        if inc.status != "open":
            return
        if inc.session_id.startswith("sim-"):
            if gw.is_active(inc.session_id, inc.agent_id) or (
                    inc.session_id in gw.sessions and gw.sessions[inc.session_id].frozen):
                if gw.agent_tier(inc.session_id, inc.agent_id) is Tier.QUARANTINED:
                    gw.release(inc.session_id, inc.agent_id, by="reviewer", note="false positive")
                    self.stats["released"] += 1
                    return
            inc.status, inc.resolved_by = "released", "reviewer"  # session already over
            self.stats["closed_after_session"] += 1
        else:
            # Confirm now (the quarantine stays); decide *whose* changes to undo in the
            # post-incident review, once the investigation knows who the attackers were.
            gw.confirm(inc.id, by="reviewer")
            self.stats["confirmed"] += 1

    def finish(self, attackers: dict[str, set[str]] | None = None) -> None:
        """Decide whatever is still queued, then run the post-incident review's compensations."""
        if not self.gw_ref:
            return
        gw = self.gw_ref[0]
        self._poll(gw)
        for inc_id, _ in self.queue:
            self._decide(gw, gw.enforcer.incidents[inc_id])
        self.queue = []
        for inc in gw.enforcer.incidents.values():
            if inc.status == "confirmed" and attackers is not None:
                bad = attackers.get(inc.session_id, set())
                self.stats["compensations"] += gw.confirm(inc.id, by="reviewer", undo_agents=bad)
                self.stats["innocent_changes_kept"] += sum(
                    1 for p in inc.proposals if p.reversible and p.entry.agent_id not in bad)


@dataclass
class StackResult:
    attacks: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    benign_sessions: int = 0
    benign_incident_sessions: int = 0
    reviewer: Counter = field(default_factory=Counter)
    runtime: Counter = field(default_factory=Counter)
    quarantine_latency_ms: list[float] = field(default_factory=list)
    rule_quarantines: int = 0
    post_release_allowed: int = 0
    post_release_enforced: int = 0
    released_agents: int = 0
    feedback_samples: int = 0
    collateral: int = 0
    fp_constraints: int = 0  # T2/T3 denials on non-attacker agents in attack sessions (scorer false positives)


def run_stack(seeds: list[int], n_benign: int, n_attacks: int, n_train: int, gae_sessions: int,
              log=print) -> StackResult:
    a, b, c = (_benign_events(n_train, s) for s in TRAIN_SEEDS)
    fast = train(a, b, c)
    det = train_gae(collect_snapshots(b, session_aggregates=True)[:gae_sessions],
                    collect_snapshots(c, session_aggregates=True))
    log("models trained")
    out = StackResult()
    for seed in seeds:
        scorer = HybridScorer(fast, det)
        gw_ref: list = []
        reviewer = Reviewer(gw_ref)
        den = Denials()
        s = generate(n_benign, seed=seed, policy=_policy(), extra_sinks=[scorer, den],
                     controllers=[scorer.controller, reviewer], attacks=ATTACKS, attacks_per_type=n_attacks)
        reviewer.gw_ref[:] = [s.gateway]
        reviewer.finish({lab.session_id: lab.attackers for lab in s.labels})
        gw = s.gateway
        out.reviewer.update(reviewer.stats)
        out.runtime.update(s.runtime)
        out.quarantine_latency_ms += scorer.quarantine_latency_ms
        out.feedback_samples += len(scorer.feedback)

        incidents_by_session: dict[str, list] = defaultdict(list)
        for inc in gw.enforcer.incidents.values():
            incidents_by_session[inc.session_id].append(inc)
            if not inc.reason.startswith(("fast path", "deep path", "session frozen")):
                out.rule_quarantines += 1

        attacked = {lab.session_id for lab in s.labels}
        for lab in s.labels:
            c = out.attacks[lab.attack]
            c["n"] += 1
            c["prevented"] += lab.prevented
            incs = incidents_by_session.get(lab.session_id, [])
            c["incident"] += bool(incs)
            c["frozen"] += lab.session_id in den.frozen
            covered = {p.entry.event_id for inc in incs for p in inc.proposals}
            for idx, executed, action in lab.harm:
                if not executed:
                    continue
                c["harm_executed"] += 1
                spec = gw.registry.tools.get(action)
                if spec is None:  # messages / spawns: nothing to undo, nothing journaled
                    c["harm_other"] += 1
                elif spec.compensation:
                    c["harm_reversible"] += 1
                    c["harm_covered"] += f"{lab.session_id}:{idx:06d}" in covered
                else:
                    c["harm_irreversible"] += 1
            # collateral: enforcement denials on agents that are neither attackers nor in a quarantine scope
            scope = {x for inc in incs for x in (inc.agent_id, *inc.subtree)} | lab.attackers
            if lab.session_id not in den.frozen:
                out.collateral += sum(1 for _, agent, rule in den.denials.get(lab.session_id, [])
                                      if rule in COLLATERAL_RULES and agent not in scope)
                out.fp_constraints += sum(1 for _, agent, rule in den.denials.get(lab.session_id, [])
                                          if rule in {"T2", "T3"} and agent not in scope)

        for sid in {e.session_id for e in gw.enforcer.incidents.values()} - attacked:
            out.benign_incident_sessions += 1
        out.benign_sessions += s.sessions - len(attacked)
        for sid, rels in den.releases.items():
            for at, agent in rels:
                out.released_agents += 1
                out.post_release_allowed += sum(1 for i, ag in den.allowed_after.get(sid, []) if i > at and ag == agent)
                out.post_release_enforced += sum(1 for i, ag, rule in den.denials.get(sid, [])
                                                 if i > at and ag == agent and rule in ENFORCEMENT_RULES)
        log(f"seed {seed} done")
    return out


# ---- report -------------------------------------------------------------------

def render(chaos: list[ChaosResult], stack: StackResult, seeds: list[int], n_benign: int, n_attacks: int) -> str:
    lines = ["# Phase 5 results: enforcement and quarantine", "",
             f"Seeds {seeds}. Regenerate with `uv run slave-eval phase5` (see `slave/eval/phase5.py`).", "",
             "## A. Chaos test: does quarantining an agent hang its siblings?", "",
             "A chaos monkey quarantines one random agent in 30% of benign sessions, at a random point. A *hang* is a "
             "live agent left waiting for a report from an agent that was quarantined, with no notice telling it to "
             "move on. *Collateral* counts agents denied as TERMINATED or FROZEN although they are outside the "
             "quarantined agent's subtree, in sessions that weren't frozen.", "",
             "| Run | Sessions | Quarantines | Hangs | Rerouted on notice | Fast-fail sends | Dead letters | "
             "Collateral denials | Gateway errors | Sessions frozen |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in chaos:
        rt = r.runtime
        lines.append(f"| {r.name} | {r.sessions:,} | {r.quarantines:,} | **{rt['hangs']}** | {rt['rerouted']} | "
                     f"{rt['fast_fail']} | {rt['dead_letter']} | {r.collateral} | {rt['gateway_errors']} | {r.frozen} |")
    with_notice = next(r for r in chaos if r.name.startswith("notices on"))
    without = next(r for r in chaos if r.name.startswith("notices off"))
    ok_a = with_notice.runtime["hangs"] == 0 and with_notice.collateral == 0 and with_notice.runtime["gateway_errors"] == 0
    lines += ["", f"**Exit criterion (zero benign-sibling hangs) {'met' if ok_a else 'NOT met'}.** With notices off, "
              f"the same chaos produces {without.runtime['hangs']} hangs, so the test can detect the failure it guards "
              "against.", ""]

    lat = sorted(stack.quarantine_latency_ms)
    p50 = statistics.median(lat) if lat else float("nan")
    p99 = lat[min(len(lat) - 1, int(0.99 * len(lat)))] if lat else float("nan")
    ok_b = bool(lat) and p99 <= QUARANTINE_BUDGET_MS
    lines += ["## B. Full stack: gate + fast path + GAE v2a + reviewer", "",
              f"Per seed: {n_benign} benign sessions and {n_attacks} sessions of each attack. A simulated reviewer "
              "looks at each incident 5 events after it opens. It releases quarantines in benign sessions and confirms "
              "the ones in attack sessions, running their reversible compensations.", "",
              "### Time to quarantine", "",
              f"Scorer-driven Tier 3 escalations: {len(lat):,}. From the scorer's decision to the quarantine being "
              f"enforced (subtree terminated, incident opened, parent notified): p50 {p50:.3f} ms, p99 {p99:.3f} ms. "
              f"Budget ≤{QUARANTINE_BUDGET_MS:.0f} ms. **Exit criterion {'met' if ok_b else 'NOT met'}.** "
              f"Rule-driven quarantines, such as P2 and session freezes, are applied inside the gate decision itself "
              f"({stack.rule_quarantines:,} incidents).", "",
              "### Attacks", "",
              "Compensations only exist for harm that was followed by a quarantine. Harm that executes while "
              "detection misses the attack opens no incident, so there is nothing to undo.", "",
              "| Attack | Prevented | Incident opened | Session frozen | Harm executed | reversible tool calls | "
              "…covered by a confirmed-incident compensation | irreversible tool calls | messages / spawns |",
              "|---|---|---|---|---|---|---|---|---|"]
    for name in ATTACKS:
        c = stack.attacks[name]
        n = c["n"]
        cov = f"{c['harm_covered']}/{c['harm_reversible']}" if c["harm_reversible"] else "–"
        lines.append(f"| {name} | {_pct(c['prevented'], n)} | {_pct(c['incident'], n)} | {_pct(c['frozen'], n)} | "
                     f"{c['harm_executed']} | {c['harm_reversible']} | {cov} | {c['harm_irreversible']} | "
                     f"{c['harm_other']} |")
    rv = stack.reviewer
    lines += ["", "### Benign traffic, release flow and runtime", "",
              f"- Benign sessions with at least one incident: {_pct(stack.benign_incident_sessions, stack.benign_sessions, 2)}.",
              f"- Reviewer: {rv['released']} released live, {rv['closed_after_session']} closed after the session ended, "
              f"{rv['confirmed']} confirmed. In the post-incident review, {rv['compensations']} attacker changes were "
              f"undone and {rv['innocent_changes_kept']} reversible changes by innocent agents were left alone. Those "
              "changes were in scope only because a session was frozen.",
              f"- Released agents: {stack.released_agents}. After release they made {stack.post_release_allowed} allowed "
              f"actions and hit {stack.post_release_enforced} enforcement denials. The scorers restart their tier "
              f"machines on release, and {stack.feedback_samples} recent score samples were recorded as calibration "
              "feedback.",
              f"- Agent runtime: {stack.runtime['rerouted']} reports rerouted on notice, {stack.runtime['hangs']} hangs, "
              f"{stack.runtime['fast_fail']} fast-fail sends, {stack.runtime['gateway_errors']} gateway errors.",
              f"- Collateral in attack sessions (TERMINATED/FROZEN denials on agents outside every quarantine scope, "
              f"frozen sessions excluded): {stack.collateral}. Separately, {stack.fp_constraints} Tier 2/3 denials hit "
              "non-attacker agents in attack sessions. Those are scorer false positives on the agents themselves, "
              "not side effects of a quarantine.", "", NOTES]
    return "\n".join(lines)


NOTES = """## Reading these numbers

- **"Hang" is modelled, not observed.** The simulator's agents are scripts, so nothing literally blocks. A hang is counted when a live agent's expected report is refused and the agent has no AGENT_QUARANTINED notice that would let a real runtime stop waiting.
- **Compensations are simulated tool calls.** `restore_file` and `git_revert` go through the fake executor. What this shows is that every reversible harmful action is *journaled, proposed and executed after confirmation*, not that a real revert succeeds.
- **The reviewer is an oracle.** It knows whether a session is benign. Real reviewers are slower and sometimes wrong, so the release numbers show the mechanism works, not how good reviewers are at the job.
- **Irreversible harm stays irreversible.** Sent emails and restarts are listed in the incident for follow-up. Nothing can undo them, which is why the synchronous gate rules matter most for egress.
"""

"""Benign swarm simulator (design.md §10, Phase 1).

Six roles (planner, researcher, coder, reviewer, data_analyst, ops) run
stochastic, parametrised workflows through the real `Gateway` on a simulated
clock. Everything is driven by one seeded RNG, and event ids/timestamps are
derived from it, so the same seed produces byte-identical event content and
therefore the same hash-chain head.

Realistic noise: test failures and fix loops, review round-trips, optional
sub-delegation, two-workflow sessions, variable think times, occasional tool
errors. Attack scenarios (A1–A8) live in `slave.sim.attacks` and run inside the
same session machinery, recording ground truth in an `AttackLabel`.
"""

from __future__ import annotations

import random
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from slave.gateway import Gateway, Policy, ToolOutput, ToolResponse, Verdict
from slave.schema import Event, EventKind
from slave.store import EventStore

SIM_EPOCH = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)
FILES = ["src/api.py", "src/models.py", "src/utils.py", "src/auth.py", "tests/test_api.py", "README.md"]
SERVICES = ["billing", "search", "auth", "ingest"]


class SimClock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class FakeTools:
    """Deterministic stand-ins for real tools."""

    def __init__(self, rng: random.Random, error_rate: float = 0.02) -> None:
        self.rng = rng
        self.error_rate = error_rate

    def __call__(self, tool: str, args: dict) -> ToolOutput:
        r = self.rng
        if tool == "run_tests":
            return ToolOutput("error" if r.random() < 0.3 else "ok")
        status = "error" if r.random() < self.error_rate else "ok"
        if tool == "sql_query":
            return ToolOutput(status, rows=r.randint(5, 2000), op="SELECT")
        if tool == "read_file":
            return ToolOutput(status, rows=1, op="READ")
        if tool == "write_file":
            return ToolOutput(status, rows=1, op="WRITE")
        return ToolOutput(status)


@dataclass(frozen=True)
class SimConfig:
    """Agent-runtime behaviour that affects provenance (over-taint mitigations)."""

    reset_on_task_boundary: bool = False  # runtime clears the planner's context between tasks
    structured_reports: bool = False  # summaries back up the tree use a schema-validated channel


@dataclass
class AttackLabel:
    """Ground truth for one attack session."""

    attack: str
    session_id: str
    attackers: set[str] = field(default_factory=set)
    first_malicious_idx: int | None = None
    harm: list[tuple[int, bool]] = field(default_factory=list)  # (event index, executed?)

    @property
    def prevented(self) -> bool:
        """No harm action executed. An attack disrupted before its first harm action counts."""
        return not any(executed for _, executed in self.harm)

    @property
    def aborted(self) -> bool:
        """The attack never reached a harm action (e.g. an earlier step was blocked)."""
        return not self.harm


class Ctx:
    """Per-session helper: think time + id allocation around gateway calls."""

    def __init__(self, gw: Gateway, clock: SimClock, rng: random.Random, session_id: str,
                 config: SimConfig = SimConfig(), label: AttackLabel | None = None) -> None:
        self.gw, self.clock, self.rng, self.sid = gw, clock, rng, session_id
        self.config = config
        self.label = label
        self.n_agents = 0

    def new_id(self, role: str) -> str:
        self.n_agents += 1
        return f"{role}-{self.n_agents:02d}"

    def think(self, lo: float = 0.5, hi: float = 4.0) -> None:
        self.clock.advance(self.rng.uniform(lo, hi))

    def spawn(self, parent: str, role: str) -> str | None:
        child = self.new_id(role)
        ok = self.gw.spawn(self.sid, parent, child, role).allowed
        self.think(0.2, 1.0)
        return child if ok else None

    def msg(self, src: str, dst: str, *, report: bool = False) -> Verdict:
        """`report=True`: a summary sent back up the tree (structured if configured)."""
        v = self.gw.send(self.sid, src, dst, token_count=self.rng.randint(50, 1500),
                         structured=report and self.config.structured_reports)
        self.think(0.2, 1.5)
        return v

    def call(self, agent: str, tool: str, **args) -> ToolResponse:
        self.think(0.3, 3.0)
        return self.gw.call_tool(self.sid, agent, tool, args)

    # ---- attack bookkeeping (ground truth) ----

    def begin_attack(self, *attackers: str) -> None:
        assert self.label is not None
        if self.label.first_malicious_idx is None:
            self.label.first_malicious_idx = self.gw.event_count(self.sid)
        self.label.attackers.update(a for a in attackers if a)

    def compromise(self, *agents: str | None) -> None:
        assert self.label is not None
        self.label.attackers.update(a for a in agents if a)

    def harm_call(self, agent: str, tool: str, **args) -> ToolResponse:
        assert self.label is not None
        self.think(0.3, 3.0)
        idx = self.gw.event_count(self.sid)
        resp = self.gw.call_tool(self.sid, agent, tool, args)
        self.label.harm.append((idx, resp.allowed))
        return resp

    def harm_msg(self, src: str, dst: str) -> bool:
        assert self.label is not None
        idx = self.gw.event_count(self.sid)
        ok = self.msg(src, dst).allowed
        self.label.harm.append((idx, ok))
        return ok

    def harm_spawn(self, parent: str, role: str) -> str | None:
        assert self.label is not None
        idx = self.gw.event_count(self.sid)
        child = self.spawn(parent, role)
        self.label.harm.append((idx, child is not None))
        return child


# ---- workflows ----------------------------------------------------------------

def code_change(c: Ctx, planner: str) -> None:
    r = c.rng
    coder, reviewer = c.spawn(planner, "coder"), c.spawn(planner, "reviewer")
    if not coder or not reviewer:
        return
    c.msg(planner, coder)
    touched = r.sample(FILES, k=r.randint(1, 3))
    for f in touched:
        c.call(coder, "read_file", store="repo", path=f)

    def edit_and_test() -> bool:
        for f in touched:
            c.call(coder, "write_file", store="repo", path=f)
        return c.call(coder, "run_tests", suite="unit").output.status == "ok"

    for _ in range(3):
        if edit_and_test():
            break
    c.call(coder, "git_diff")
    c.msg(coder, reviewer)
    c.call(reviewer, "git_diff")
    if r.random() < 0.5:
        c.call(reviewer, "run_tests", suite="unit")
    if r.random() < 0.3:  # review asks for changes
        c.msg(reviewer, coder)
        edit_and_test()
        c.msg(coder, reviewer)
    c.msg(reviewer, coder)
    c.call(coder, "git_commit", message=f"change-{r.getrandbits(20):05x}")
    c.msg(coder, planner, report=True)


def _research(c: Ctx, researcher: str, depth_budget: int) -> None:
    r = c.rng
    for _ in range(r.randint(2, 5)):
        c.call(researcher, "search", q=f"topic-{r.randint(1, 60)}")
        for _ in range(r.randint(1, 3)):
            c.call(researcher, "web_fetch", url=f"https://example.org/{r.getrandbits(24):06x}")
    if depth_budget and r.random() < 0.3:
        sub = c.spawn(researcher, "researcher")
        if sub:
            c.msg(researcher, sub)
            _research(c, sub, depth_budget - 1)
            c.msg(sub, researcher, report=True)
    c.call(researcher, "read_file", store="docs", path="notes.md")


def research_report(c: Ctx, planner: str) -> None:
    researcher = c.spawn(planner, "researcher")
    if not researcher:
        return
    c.msg(planner, researcher)
    _research(c, researcher, depth_budget=1)
    c.msg(researcher, planner, report=True)
    if c.rng.random() < 0.5:
        analyst = c.spawn(planner, "data_analyst")
        if analyst:
            c.msg(planner, analyst)
            c.call(analyst, "sql_query", store="sales_db", query=f"q{c.rng.randint(1, 40)}")
            c.call(analyst, "write_file", store="docs", path="report.md")
            c.msg(analyst, planner, report=True)


def data_question(c: Ctx, planner: str) -> None:
    analyst = c.spawn(planner, "data_analyst")
    if not analyst:
        return
    c.msg(planner, analyst)
    store = "customers_db" if c.rng.random() < 0.3 else "sales_db"  # pii in ~30% of questions
    for _ in range(c.rng.randint(2, 6)):
        c.call(analyst, "sql_query", store=store, query=f"q{c.rng.randint(1, 40)}")
    c.call(analyst, "write_file", store="docs", path="analysis.md")
    c.msg(analyst, planner, report=True)


def ops_incident(c: Ctx, planner: str) -> None:
    r = c.rng
    ops = c.spawn(planner, "ops")
    if not ops:
        return
    svc = r.choice(SERVICES)
    c.msg(planner, ops)
    for i in range(r.randint(2, 5)):
        c.call(ops, "read_logs", service=svc, window=i)
    c.call(ops, "read_file", store="docs", path=f"runbooks/{svc}.md")
    if r.random() < 0.6:
        c.call(ops, "restart_service", service=svc)
        c.call(ops, "read_logs", service=svc, window="after-restart")
    c.call(ops, "send_email", to="oncall", subject=f"{svc} incident update")
    c.msg(ops, planner, report=True)


WORKFLOWS: dict[str, tuple[Callable[[Ctx, str], None], float]] = {
    "code_change": (code_change, 0.40),
    "research_report": (research_report, 0.25),
    "data_question": (data_question, 0.20),
    "ops_incident": (ops_incident, 0.15),
}


def _pick_workflow(rng: random.Random) -> str:
    names = list(WORKFLOWS)
    return rng.choices(names, weights=[WORKFLOWS[n][1] for n in names])[0]


# ---- driver -------------------------------------------------------------------

@dataclass
class SimSummary:
    sessions: int = 0
    labels: list[AttackLabel] = field(default_factory=list)
    events: int = 0
    workflows: Counter = field(default_factory=Counter)
    roles: Counter = field(default_factory=Counter)
    kinds: Counter = field(default_factory=Counter)
    denials: Counter = field(default_factory=Counter)
    gate_p50_ms: float | None = None
    gate_p99_ms: float | None = None
    gate_max_ms: float | None = None
    head_hash: str | None = None
    elapsed_s: float = 0.0


AttackFn = Callable[[Ctx, str], None]


def run_session(gw: Gateway, clock: SimClock, rng: random.Random, session_id: str,
                config: SimConfig = SimConfig(), attack: tuple[str, AttackFn] | None = None
                ) -> tuple[list[str], AttackLabel | None]:
    """One session: 1–2 benign workflows; an attack session also runs its attack."""
    label = AttackLabel(attack[0], session_id) if attack else None
    c = Ctx(gw, clock, rng, session_id, config, label)
    planner = c.new_id("planner")
    gw.open_session(session_id, planner, "planner")
    c.call(planner, "read_file", store="docs", path="task.md")
    chosen = [_pick_workflow(rng)]
    if attack is None and rng.random() < 0.2:
        chosen.append(_pick_workflow(rng))
    plan: list[tuple[str, Callable[[Ctx, str], None]]] = [(n, WORKFLOWS[n][0]) for n in chosen]
    if attack:
        # attack either follows benign work or happens first
        plan.insert(rng.randint(0, len(plan)), (f"attack:{attack[0]}", attack[1]))
    for i, (_name, fn) in enumerate(plan):
        if i and config.reset_on_task_boundary:
            gw.reset_context(session_id, planner)
        fn(c, planner)
        c.think(1.0, 6.0)
    gw.close_session(session_id)
    return chosen, label


def generate(n_sessions: int, seed: int = 1, store: EventStore | None = None,
             extra_sinks: list[Callable[[Event], Event | None]] | None = None, *,
             policy: Policy | None = None, config: SimConfig = SimConfig(),
             attacks: dict[str, AttackFn] | None = None, attacks_per_type: int = 0,
             controllers: list | None = None) -> SimSummary:
    """Run `n_sessions` benign sessions plus `attacks_per_type` sessions of each attack, interleaved."""
    rng = random.Random(seed)
    clock = SimClock(SIM_EPOCH)
    summary = SimSummary()

    def count(ev: Event) -> None:
        summary.events += 1
        summary.kinds[ev.kind.value] += 1
        if ev.kind is EventKind.SPAWN and ev.dst_role:
            summary.roles[ev.dst_role] += 1
        if ev.kind is EventKind.GATE_DECISION and ev.decision != "allow":
            summary.denials[ev.rule or "?"] += 1

    sinks: list = [store] if store is not None else []
    sinks += [count, *(extra_sinks or [])]
    gw = Gateway(policy=policy, executor=FakeTools(rng), sinks=sinks, clock=clock, latency_in_events=False,
                 controllers=controllers or ())

    plans: list[tuple[str, AttackFn] | None] = [None] * n_sessions
    for name, fn in (attacks or {}).items():
        plans += [(name, fn)] * attacks_per_type
    if attacks_per_type:
        rng.shuffle(plans)

    t0 = time.perf_counter()
    start = SIM_EPOCH
    for i, attack in enumerate(plans):
        start += timedelta(seconds=rng.expovariate(1 / 20))  # ~1 new session / 20 s
        clock.now = start
        prefix = "atk" if attack else "sim"
        workflows, label = run_session(gw, clock, rng, f"{prefix}-{seed}-{i:06d}", config, attack)
        for wf in workflows:
            summary.workflows[wf] += 1
        if label:
            summary.labels.append(label)
        summary.sessions += 1
        if store is not None:
            store.maybe_flush()  # between sessions: never inside a gate decision
    if store is not None:
        store.flush()
        summary.head_hash = store.head_hash
    summary.elapsed_s = time.perf_counter() - t0
    summary.gate_p50_ms = gw.latency_percentile(0.50)
    summary.gate_p99_ms = gw.latency_percentile(0.99)
    summary.gate_max_ms = max(gw.gate_latency_ms, default=None)
    return summary

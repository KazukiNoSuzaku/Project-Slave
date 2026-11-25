"""Scripted demo feed for the dashboard.

This is NOT the swarm simulator from design.md §10 — it is a deterministic,
hand-scripted event stream (including the control-plane decisions the real
gate and scorers will make later) so the UI can be built and demoed before the
detection pipeline exists. Each cycle plays four sessions concurrently:

* a benign coding session
* A1 — indirect prompt injection → payroll query, blocked by P1, quarantined
* A4 — runaway spawn chain, stopped by the P4 depth cap
* A5 — planner ↔ reviewer ping-pong loop, elevated by the fast path
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from slave.schema import Event, EventKind, NodeType, SideEffect, Tier, Trust

# tool -> (side effect, trust of its output, data classes of its output)
TOOLS: dict[str, tuple[SideEffect, Trust, frozenset[str]]] = {
    "web_fetch": (SideEffect.READ_ONLY, Trust.UNTRUSTED, frozenset()),
    "search": (SideEffect.READ_ONLY, Trust.UNTRUSTED, frozenset()),
    "read_file": (SideEffect.READ_ONLY, Trust.INTERNAL, frozenset()),
    "git_diff": (SideEffect.READ_ONLY, Trust.INTERNAL, frozenset()),
    "run_tests": (SideEffect.READ_ONLY, Trust.INTERNAL, frozenset()),
    "write_file": (SideEffect.MUTATING, Trust.INTERNAL, frozenset()),
    "git_commit": (SideEffect.MUTATING, Trust.INTERNAL, frozenset()),
    "sql_query": (SideEffect.READ_ONLY, Trust.INTERNAL, frozenset()),
    "send_email": (SideEffect.EXTERNAL_EGRESS, Trust.INTERNAL, frozenset()),
}


@dataclass(frozen=True)
class Step:
    at: float  # seconds from cycle start
    event: Event


class _Script:
    def __init__(self, session_id: str, rng: random.Random, base: datetime, start: float = 0.0):
        self.sid = session_id
        self.rng = rng
        self.base = base
        self.t = start
        self.steps: list[Step] = []

    def wait(self, lo: float = 0.4, hi: float = 1.6) -> None:
        self.t += self.rng.uniform(lo, hi)

    def add(self, **kw) -> None:
        ev = Event(session_id=self.sid, ts=self.base + timedelta(seconds=self.t), **kw)
        self.steps.append(Step(self.t, ev))

    def spawn(self, parent: str, child: str, role: str, parent_role: str | None = None) -> None:
        self.add(kind=EventKind.SPAWN, src_id=parent, src_role=parent_role, dst_id=child,
                 dst_role=role, dst_type=NodeType.AGENT)
        self.wait()

    def msg(self, src: str, dst: str) -> None:
        self.add(kind=EventKind.MSG_SEND, src_id=src, dst_id=dst, dst_type=NodeType.AGENT)
        self.wait(0.2, 0.8)

    def call(self, agent: str, tool: str, *, deny_rule: str | None = None, reason: str | None = None,
             data_classes: frozenset[str] | None = None) -> None:
        side_effect, trust, classes = TOOLS[tool]
        self.add(kind=EventKind.TOOL_CALL, src_id=agent, dst_id=tool, dst_type=NodeType.TOOL,
                 side_effect=side_effect)
        latency = round(self.rng.lognormvariate(0.2, 0.45), 2)
        self.add(kind=EventKind.GATE_DECISION, src_id=agent, dst_id=tool,
                 decision="deny" if deny_rule else "allow", rule=deny_rule, reason=reason,
                 latency_ms=latency)
        if deny_rule is None:
            self.wait(0.1, 0.5)
            self.add(kind=EventKind.TOOL_RESULT, src_id=agent, dst_id=tool, trust=trust,
                     data_classes=set(data_classes if data_classes is not None else classes))
        self.wait()

    def score(self, agent: str, p_star: float, reason: str) -> None:
        self.add(kind=EventKind.SCORE, src_id=agent, p_star=p_star, reason=reason)
        self.wait(0.1, 0.3)

    def tier(self, agent: str, tier: Tier, reason: str) -> None:
        self.add(kind=EventKind.TIER_CHANGE, src_id=agent, tier=tier, reason=reason)
        self.wait(0.1, 0.3)


def _sid(rng: random.Random) -> str:
    return f"sess-{rng.getrandbits(16):04x}"


def _benign(s: _Script) -> None:
    s.spawn("planner-01", "coder-03", "coder", "planner")
    s.spawn("planner-01", "reviewer-05", "reviewer", "planner")
    s.msg("planner-01", "coder-03")
    for _ in range(2):
        s.call("coder-03", "read_file")
        s.call("coder-03", "git_diff")
        s.call("coder-03", "write_file")
        s.call("coder-03", "run_tests")
    s.msg("coder-03", "reviewer-05")
    s.call("reviewer-05", "git_diff")
    s.msg("reviewer-05", "coder-03")
    s.call("coder-03", "git_commit")
    s.msg("coder-03", "planner-01")


def _a1_injection(s: _Script) -> None:
    s.spawn("planner-01", "research-02", "researcher", "planner")
    s.spawn("planner-01", "analyst-04", "analyst", "planner")
    s.msg("planner-01", "research-02")
    s.call("analyst-04", "sql_query")
    s.call("research-02", "search")
    s.call("research-02", "web_fetch")  # page carries hidden instructions
    s.wait(1.0, 2.0)
    s.call("research-02", "sql_query", deny_rule="P1",
           reason="untrusted context → restricted payroll")
    s.tier("research-02", Tier.CONSTRAINED, "P1 rule hit")
    s.wait(1.5, 2.5)
    s.score("research-02", 1.2e-4, "gae.node=4e-5 fast=2e-3 transition_unseen")
    s.tier("research-02", Tier.QUARANTINED, "P1 + p*<1e-4 · token revoked")
    s.call("analyst-04", "sql_query")


def _a4_spawn_bomb(s: _Script) -> None:
    s.spawn("planner-01", "coder-09", "coder", "planner")
    parent = "coder-09"
    for depth in range(1, 6):
        child = f"coder-09.{depth}"
        s.spawn(parent, child, "coder")
        s.wait(0.1, 0.4)
        parent = child
    s.add(kind=EventKind.TOOL_CALL, src_id=parent, dst_id="spawn_agent", dst_type=NodeType.TOOL)
    s.add(kind=EventKind.GATE_DECISION, src_id=parent, dst_id="spawn_agent", decision="deny",
          rule="P4", reason="spawn depth 6 > cap 5", latency_ms=0.6)
    s.wait()
    s.tier("coder-09", Tier.CONSTRAINED, "P4 spawn cap")


def _a5_loop(s: _Script) -> None:
    s.spawn("planner-01", "reviewer-07", "reviewer", "planner")
    for _ in range(14):
        s.msg("planner-01", "reviewer-07")
        s.msg("reviewer-07", "planner-01")
    s.score("reviewer-07", 6e-3, "ping-pong ×14")
    s.tier("reviewer-07", Tier.ELEVATED, "fast path: loop frequency")


SCENARIOS: list[tuple[str, Callable[[_Script], None], float]] = [
    ("benign", _benign, 0.0),
    ("A1", _a1_injection, 3.0),
    ("A4", _a4_spawn_bomb, 12.0),
    ("A5", _a5_loop, 6.0),
]


def build_cycle(rng: random.Random, base: datetime | None = None) -> list[Step]:
    """One demo cycle: all scenarios interleaved, ordered by time."""
    base = base or datetime.now(timezone.utc)
    steps: list[Step] = []
    for _name, fn, start in SCENARIOS:
        script = _Script(_sid(rng), rng, base, start)
        fn(script)
        steps.extend(script.steps)
    steps.sort(key=lambda st: st.at)
    return steps


async def run_demo(sink: Callable[[Event], Awaitable[None]], *, seed: int = 7,
                   speed: float = 1.0, pause: float = 8.0) -> None:
    """Play demo cycles forever, re-stamping events with wall-clock time."""
    rng = random.Random(seed)
    while True:
        prev = 0.0
        for step in build_cycle(rng):
            await asyncio.sleep(max(0.0, step.at - prev) / speed)
            prev = step.at
            await sink(step.event.model_copy(update={"ts": datetime.now(timezone.utc)}))
        await asyncio.sleep(pause / speed)

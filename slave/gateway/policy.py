"""Synchronous gate policy — Phase 1 rules (design.md §2.1, §3.2 P4).

Rules are evaluated in order; the first that fires decides. Provenance rules
P1–P3 arrive in Phase 2 and slot in after the tier rules.

| Rule | Fires when |
|------|-----------|
| T3   | agent is quarantined — everything denied |
| T2   | agent is constrained — mutating / egress tools and spawning denied |
| S1   | role may not use this tool (or may not spawn) |
| S2   | effective sensitivity of the call exceeds the agent's privilege tier |
| P4   | caps: spawn depth, spawn fan-out, spawn rate, call rate, identical-call repeats |
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

from slave.registry import Registry, ToolSpec
from slave.schema import SideEffect, Tier

Action = Literal["tool", "spawn", "message"]


@dataclass(frozen=True)
class Caps:
    max_spawn_depth: int = 4
    max_children_per_agent: int = 6
    max_spawns_per_minute: int = 12  # per session
    max_calls_per_minute: int = 60  # per agent
    max_identical_calls: int = 6  # same (tool, args) per agent within the window
    window: timedelta = timedelta(minutes=1)


@dataclass
class AgentState:
    agent_id: str
    session_id: str
    role: str
    privilege_tier: int
    parent_id: str | None = None
    depth: int = 0
    tier: Tier = Tier.NORMAL
    children: int = 0
    recent_calls: deque[tuple[datetime, str]] = field(default_factory=deque)


@dataclass
class SessionState:
    session_id: str
    agents: dict[str, AgentState] = field(default_factory=dict)
    recent_spawns: deque[datetime] = field(default_factory=deque)


@dataclass(frozen=True)
class Verdict:
    decision: Literal["allow", "deny"]
    rule: str | None = None
    reason: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


ALLOW = Verdict("allow")


def _deny(rule: str, reason: str) -> Verdict:
    return Verdict("deny", rule, reason)


def _trim(dq: deque, now: datetime, window: timedelta, key=lambda x: x) -> None:
    while dq and now - key(dq[0]) > window:
        dq.popleft()


class Policy:
    def __init__(self, registry: Registry, caps: Caps | None = None) -> None:
        self.registry = registry
        self.caps = caps or Caps()

    def check_tool(self, sess: SessionState, agent: AgentState, tool: ToolSpec | None, tool_name: str,
                   args: dict, args_hash: str, now: datetime) -> Verdict:
        if (v := self._tier(agent, risky=tool is None or tool.side_effect is not SideEffect.READ_ONLY)):
            return v
        role = self.registry.roles[agent.role]
        if tool is None:
            return _deny("S1", f"unknown tool {tool_name}")
        if tool_name not in role.tools:
            return _deny("S1", f"role {agent.role} may not call {tool_name}")
        if tool.uses_store and self.registry.store_for(tool, args) is None:
            return _deny("S1", f"unknown store {args.get('store')!r}")
        sens = self.registry.effective_sensitivity(tool, args)
        if sens > agent.privilege_tier:
            return _deny("S2", f"sensitivity {sens} > privilege {agent.privilege_tier}")

        caps = self.caps
        _trim(agent.recent_calls, now, caps.window, key=lambda x: x[0])
        if len(agent.recent_calls) >= caps.max_calls_per_minute:
            return _deny("P4", f"call rate > {caps.max_calls_per_minute}/min")
        repeats = sum(1 for _, h in agent.recent_calls if h == args_hash)
        if repeats >= caps.max_identical_calls:
            return _deny("P4", f"identical {tool_name} call repeated {repeats + 1}×")
        return ALLOW

    def check_spawn(self, sess: SessionState, parent: AgentState, child_role: str, now: datetime) -> Verdict:
        if (v := self._tier(parent, risky=True)):
            return v
        role = self.registry.roles[parent.role]
        if not role.can_spawn:
            return _deny("S1", f"role {parent.role} may not spawn")
        if child_role not in self.registry.roles:
            return _deny("S1", f"unknown role {child_role}")
        # Delegating to a higher-privilege role is allowed statically; abuse of
        # it (confused deputy) is rule P3, which needs provenance (Phase 2).
        caps = self.caps
        if parent.depth + 1 > caps.max_spawn_depth:
            return _deny("P4", f"spawn depth {parent.depth + 1} > cap {caps.max_spawn_depth}")
        if parent.children >= caps.max_children_per_agent:
            return _deny("P4", f"fan-out > {caps.max_children_per_agent}")
        _trim(sess.recent_spawns, now, caps.window)
        if len(sess.recent_spawns) >= caps.max_spawns_per_minute:
            return _deny("P4", f"spawn rate > {caps.max_spawns_per_minute}/min")
        return ALLOW

    def check_message(self, sender: AgentState) -> Verdict:
        if sender.tier is Tier.QUARANTINED:
            return _deny("T3", "sender quarantined")
        return ALLOW

    @staticmethod
    def _tier(agent: AgentState, *, risky: bool) -> Verdict | None:
        if agent.tier is Tier.QUARANTINED:
            return _deny("T3", "agent quarantined")
        if agent.tier is Tier.CONSTRAINED and risky:
            return _deny("T2", "agent constrained: mutating/egress/spawn revoked")
        return None

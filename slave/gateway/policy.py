"""Synchronous gate policy (design.md §2.1, §3.2).

Rules are evaluated in order; the first that fires decides.

| Rule | Fires when | Outcome |
|------|-----------|---------|
| T3 | agent is quarantined | deny everything |
| T2 | agent is constrained | deny mutating / egress tools and spawning |
| S1 | role may not use this tool (or may not spawn) | deny |
| S2 | effective sensitivity of the call > agent's privilege tier | deny |
| P2 | context holds pii/restricted data ∧ tool is external egress | deny + escalate to Tier 3 |
| P1 | context is untrusted ∧ tool mutates or egresses ∧ sensitivity ≥ threshold | require human approval |
| P3 | an *untrusted*, lower-privilege agent recently asked this agent (message or spawn) ∧ the call's sensitivity exceeds the requester's privilege | deny + escalate to Tier 2 |
| P4 | caps: spawn depth, fan-out, spawn rate, call rate (lower at Tier 1), identical-call repeats | deny |

Before any of these: actions by terminated agents (TERMINATED) and by any agent
in a frozen session (FROZEN) are denied, and messages to a quarantined or
terminated agent fail fast with DST_UNAVAILABLE.

P1–P3 read the agent's provenance label (`AgentState.trust`, `.labels`),
which the gateway maintains. They are active only when `ProvenanceRules` is
passed (ablation rung R1 runs without them).

P3 refines design v2: requests from lower-privilege agents are normal
delegation (planner → ops). Only requests whose sender context is untrusted
are treated as possible confused-deputy attempts.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

from slave.registry import Registry, ToolSpec
from slave.schema import SideEffect, Tier, Trust

Action = Literal["tool", "spawn", "message"]


@dataclass(frozen=True)
class Caps:
    max_spawn_depth: int = 4
    max_children_per_agent: int = 6
    max_spawns_per_minute: int = 12  # per session
    max_calls_per_minute: int = 60  # per agent
    max_identical_calls: int = 6  # same (tool, args) per agent within the window
    max_calls_per_minute_elevated: int = 20  # Tier 1 soft rate limit
    window: timedelta = timedelta(minutes=1)


@dataclass(frozen=True)
class ProvenanceRules:
    p1_min_sensitivity: int = 3
    sensitive_classes: frozenset[str] = frozenset({"pii", "restricted"})
    p3_window: timedelta = timedelta(minutes=10)


@dataclass
class Request:
    """A message or spawn from a lower-privilege agent with an untrusted context."""

    at: datetime
    sender: str
    sender_privilege: int


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
    # provenance label of everything that has entered this agent's context
    trust: Trust = Trust.SYSTEM
    labels: set[str] = field(default_factory=set)
    untrusted_requests: deque[Request] = field(default_factory=deque)
    terminated: bool = False  # killed as part of a quarantined subtree


@dataclass
class SessionState:
    session_id: str
    agents: dict[str, AgentState] = field(default_factory=dict)
    recent_spawns: deque[datetime] = field(default_factory=deque)
    frozen: bool = False  # whole session halted (compromised orchestrator); human release only


@dataclass(frozen=True)
class Verdict:
    decision: Literal["allow", "deny", "approve_required"]
    rule: str | None = None
    reason: str | None = None
    escalate: Tier | None = None  # tier the gateway should raise the agent to

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


ALLOW = Verdict("allow")


def _deny(rule: str, reason: str, escalate: Tier | None = None) -> Verdict:
    return Verdict("deny", rule, reason, escalate)


def _trim(dq: deque, now: datetime, window: timedelta, key=lambda x: x) -> None:
    while dq and now - key(dq[0]) > window:
        dq.popleft()


class Policy:
    def __init__(self, registry: Registry, caps: Caps | None = None,
                 provenance: ProvenanceRules | None = None) -> None:
        self.registry = registry
        self.caps = caps or Caps()
        self.provenance = provenance

    def check_tool(self, sess: SessionState, agent: AgentState, tool: ToolSpec | None, tool_name: str,
                   args: dict, args_hash: str, now: datetime) -> Verdict:
        if (v := self._alive(sess, agent)):
            return v
        if (v := self._tier(agent, risky=tool is None or tool.side_effect is not SideEffect.READ_ONLY)):
            return v
        role = self.registry.roles[agent.role]
        if tool is None:
            return _deny("S1", f"unknown tool {tool_name}")
        if tool_name not in role.tools:  # also keeps agents off the system-only compensation tools
            return _deny("S1", f"role {agent.role} may not call {tool_name}")
        if tool.uses_store and self.registry.store_for(tool, args) is None:
            return _deny("S1", f"unknown store {args.get('store')!r}")
        sens = self.registry.effective_sensitivity(tool, args)
        if sens > agent.privilege_tier:
            return _deny("S2", f"sensitivity {sens} > privilege {agent.privilege_tier}")
        if self.provenance and (v := self._provenance(agent, tool, sens, now)):
            return v
        return self._call_caps(agent, tool_name, args_hash, now)

    def _provenance(self, agent: AgentState, tool: ToolSpec, sens: int, now: datetime) -> Verdict | None:
        rules = self.provenance
        assert rules is not None
        held = agent.labels & rules.sensitive_classes
        if held and tool.side_effect is SideEffect.EXTERNAL_EGRESS:
            return _deny("P2", f"context holds {','.join(sorted(held))} → egress via {tool.name}",
                         escalate=Tier.QUARANTINED)
        if (agent.trust is Trust.UNTRUSTED and tool.side_effect is not SideEffect.READ_ONLY
                and sens >= rules.p1_min_sensitivity):
            return Verdict("approve_required", "P1",
                           f"untrusted context → {tool.side_effect.value} {tool.name} (sensitivity {sens})")
        _trim(agent.untrusted_requests, now, rules.p3_window, key=lambda r: r.at)
        for req in agent.untrusted_requests:
            if sens > req.sender_privilege:
                return _deny("P3", f"untrusted request from {req.sender} (privilege {req.sender_privilege}) "
                                   f"→ sensitivity {sens}", escalate=Tier.CONSTRAINED)
        return None

    def _call_caps(self, agent: AgentState, tool_name: str, args_hash: str, now: datetime) -> Verdict:
        caps = self.caps
        _trim(agent.recent_calls, now, caps.window, key=lambda x: x[0])
        limit = caps.max_calls_per_minute_elevated if agent.tier is Tier.ELEVATED else caps.max_calls_per_minute
        if len(agent.recent_calls) >= limit:
            return _deny("P4", f"call rate > {limit}/min" + (" (Tier 1 soft limit)" if agent.tier is Tier.ELEVATED else ""))
        repeats = sum(1 for _, h in agent.recent_calls if h == args_hash)
        if repeats >= caps.max_identical_calls:
            return _deny("P4", f"identical {tool_name} call repeated {repeats + 1}×")
        return ALLOW

    def check_spawn(self, sess: SessionState, parent: AgentState, child_role: str, now: datetime) -> Verdict:
        if (v := self._alive(sess, parent)):
            return v
        if (v := self._tier(parent, risky=True)):
            return v
        role = self.registry.roles[parent.role]
        if not role.can_spawn:
            return _deny("S1", f"role {parent.role} may not spawn")
        if child_role not in self.registry.roles:
            return _deny("S1", f"unknown role {child_role}")
        caps = self.caps
        if parent.depth + 1 > caps.max_spawn_depth:
            return _deny("P4", f"spawn depth {parent.depth + 1} > cap {caps.max_spawn_depth}")
        if parent.children >= caps.max_children_per_agent:
            return _deny("P4", f"fan-out > {caps.max_children_per_agent}")
        _trim(sess.recent_spawns, now, caps.window)
        if len(sess.recent_spawns) >= caps.max_spawns_per_minute:
            return _deny("P4", f"spawn rate > {caps.max_spawns_per_minute}/min")
        return ALLOW

    def check_message(self, sess: SessionState, sender: AgentState, receiver: AgentState) -> Verdict:
        if (v := self._alive(sess, sender)):
            return v
        if sender.tier is Tier.QUARANTINED:
            return _deny("T3", "sender quarantined")
        if receiver.terminated or receiver.tier is Tier.QUARANTINED:
            # fail fast with a structured reason instead of leaving the sender waiting
            return _deny("DST_UNAVAILABLE", f"{receiver.agent_id} is quarantined")
        return ALLOW

    @staticmethod
    def _alive(sess: SessionState, agent: AgentState) -> Verdict | None:
        if agent.terminated:
            return _deny("TERMINATED", "agent was terminated with a quarantined subtree")
        if sess.frozen:
            return _deny("FROZEN", "session frozen pending human review")
        return None

    @staticmethod
    def _tier(agent: AgentState, *, risky: bool) -> Verdict | None:
        if agent.tier is Tier.QUARANTINED:
            return _deny("T3", "agent quarantined")
        if agent.tier is Tier.CONSTRAINED and risky:
            return _deny("T2", "agent constrained: mutating/egress/spawn revoked")
        return None

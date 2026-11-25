"""The gateway: the single choke point between agents and tools (design.md §1, §2).

Agents never hold tool credentials; every spawn, message and tool call goes
through `Gateway`, which

1. captures the interaction as `Event`s,
2. runs the synchronous gate (`Policy`) *before* anything executes,
3. executes allowed tool calls via the injected `executor`,
4. hands every event to its sinks (event store first, then e.g. the dashboard).

Timestamps come from an injectable clock so the simulator can run on simulated
time; gate latency is always measured on the real wall clock.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from slave.gateway.policy import AgentState, Policy, ProvenanceRules, Request, SessionState, Verdict
from slave.registry import Registry, default_registry
from slave.schema import Event, EventKind, NodeType, Tier, Trust, join_trust


class GatewayError(Exception):
    """Protocol misuse: unknown session/agent, duplicate ids."""


@dataclass(frozen=True)
class ToolOutput:
    status: Literal["ok", "error"] = "ok"
    result: Any = None
    rows: int | None = None
    op: str | None = None  # DATA_ACCESS operation, e.g. SELECT / WRITE


@dataclass(frozen=True)
class ToolResponse:
    allowed: bool
    rule: str | None = None
    reason: str | None = None
    output: ToolOutput | None = None


Executor = Callable[[str, dict], ToolOutput]
Sink = Callable[[Event], "Event | None"]  # may return a replacement (e.g. sealed) event
# Human-in-the-loop for P1: (agent, tool, args, verdict) -> approved?
Approver = Callable[[AgentState, str, dict, Verdict], bool]
# Runs after every gated action, outside the gate's latency path. Used by the
# behavioural scorer to push tier changes the gate will see on the next action.
Controller = Callable[["Gateway", str], None]


def _default_executor(tool: str, args: dict) -> ToolOutput:
    raise GatewayError(f"no executor configured for tool {tool!r}")


def args_hash(tool: str, args: dict) -> str:
    blob = json.dumps([tool, args], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Gateway:
    def __init__(
        self,
        registry: Registry | None = None,
        *,
        policy: Policy | None = None,
        executor: Executor = _default_executor,
        sinks: Iterable[Sink] = (),
        clock: Callable[[], datetime] = _utcnow,
        latency_in_events: bool = True,
        approver: Approver | None = None,
        controllers: Iterable[Controller] = (),
    ) -> None:
        self.registry = registry or default_registry()
        self.policy = policy or Policy(self.registry, provenance=ProvenanceRules())
        self.approver = approver
        self.controllers = list(controllers)
        self.executor = executor
        self.sinks = list(sinks)
        self.clock = clock
        # Wall-clock latency makes event content non-reproducible; the simulator
        # turns it off and reads `gate_latency_ms` instead.
        self.latency_in_events = latency_in_events
        self.sessions: dict[str, SessionState] = {}
        self.gate_latency_ms: list[float] = []
        self._event_counter: dict[str, int] = {}

    # ---- plumbing -----------------------------------------------------------

    def _emit(self, session_id: str, **fields: Any) -> Event:
        n = self._event_counter.get(session_id, 0)
        self._event_counter[session_id] = n + 1
        event = Event(event_id=f"{session_id}:{n:06d}", session_id=session_id, ts=self.clock(), **fields)
        for sink in self.sinks:
            event = sink(event) or event
        return event

    def _session(self, session_id: str) -> SessionState:
        try:
            return self.sessions[session_id]
        except KeyError:
            raise GatewayError(f"unknown session {session_id!r}") from None

    @staticmethod
    def _agent(sess: SessionState, agent_id: str) -> AgentState:
        try:
            return sess.agents[agent_id]
        except KeyError:
            raise GatewayError(f"unknown agent {agent_id!r} in {sess.session_id}") from None

    def _gate(self, session_id: str, agent: AgentState, dst: str, verdict: Verdict, t0: float) -> None:
        latency = (time.perf_counter() - t0) * 1000
        self.gate_latency_ms.append(latency)
        self._emit(session_id, kind=EventKind.GATE_DECISION, src_id=agent.agent_id, src_role=agent.role,
                   dst_id=dst, decision=verdict.decision, rule=verdict.rule, reason=verdict.reason,
                   latency_ms=round(latency, 4) if self.latency_in_events else None)
        if verdict.escalate is not None and verdict.escalate > agent.tier:
            self.set_tier(session_id, agent.agent_id, verdict.escalate, f"{verdict.rule}: {verdict.reason}")

    # ---- provenance ---------------------------------------------------------

    @staticmethod
    def _absorb(agent: AgentState, trust: Trust, labels: set[str] | frozenset[str]) -> None:
        agent.trust = join_trust(agent.trust, trust)
        agent.labels |= labels

    def _note_request(self, sender: AgentState, receiver: AgentState) -> None:
        """Remember untrusted requests flowing up the privilege ladder (input to P3)."""
        if sender.trust is Trust.UNTRUSTED and sender.privilege_tier < receiver.privilege_tier:
            receiver.untrusted_requests.append(Request(self.clock(), sender.agent_id, sender.privilege_tier))

    # ---- session lifecycle --------------------------------------------------

    def open_session(self, session_id: str, root_id: str, root_role: str, *, opened_by: str = "user") -> None:
        if session_id in self.sessions:
            raise GatewayError(f"session {session_id!r} already open")
        role = self.registry.roles.get(root_role)
        if role is None:
            raise GatewayError(f"unknown role {root_role!r}")
        sess = self.sessions[session_id] = SessionState(session_id)
        sess.agents[root_id] = AgentState(root_id, session_id, root_role, role.privilege_tier)
        self._emit(session_id, kind=EventKind.SPAWN, src_id=opened_by, src_role=opened_by, dst_id=root_id,
                   dst_role=root_role, dst_type=NodeType.AGENT, spawn_depth=0,
                   privilege_tier=role.privilege_tier)

    def close_session(self, session_id: str) -> None:
        sess = self._session(session_id)
        for agent in reversed(list(sess.agents.values())):
            self._emit(session_id, kind=EventKind.TERMINATE, src_id=agent.agent_id, src_role=agent.role)
        del self.sessions[session_id]
        self._event_counter.pop(session_id, None)

    # ---- gated actions ------------------------------------------------------

    def _after(self, session_id: str) -> None:
        for ctl in self.controllers:
            ctl(self, session_id)

    def spawn(self, session_id: str, parent_id: str, child_id: str, child_role: str) -> Verdict:
        verdict = self._spawn(session_id, parent_id, child_id, child_role)
        self._after(session_id)
        return verdict

    def send(self, session_id: str, src_id: str, dst_id: str, *, token_count: int | None = None,
             structured: bool = False) -> Verdict:
        """Agent-to-agent message. A gate decision is recorded only on denial.

        `structured=True` means the payload went through a schema-validated
        channel (no free text). That declassifies *trust* — instructions can't
        ride along — but data classes still propagate.
        """
        verdict = self._send(session_id, src_id, dst_id, token_count=token_count, structured=structured)
        self._after(session_id)
        return verdict

    def call_tool(self, session_id: str, agent_id: str, tool_name: str, args: dict | None = None) -> ToolResponse:
        resp = self._call_tool(session_id, agent_id, tool_name, args)
        self._after(session_id)
        return resp

    def _spawn(self, session_id: str, parent_id: str, child_id: str, child_role: str) -> Verdict:
        t0 = time.perf_counter()
        sess = self._session(session_id)
        parent = self._agent(sess, parent_id)
        if child_id in sess.agents:
            raise GatewayError(f"agent {child_id!r} already exists in {session_id}")
        now = self.clock()
        verdict = self.policy.check_spawn(sess, parent, child_role, now)
        self._gate(session_id, parent, "spawn_agent", verdict, t0)
        if not verdict.allowed:
            return verdict
        role = self.registry.roles[child_role]
        child = sess.agents[child_id] = AgentState(child_id, session_id, child_role, role.privilege_tier,
                                                   parent_id=parent_id, depth=parent.depth + 1)
        self._absorb(child, parent.trust, parent.labels)  # child starts with the parent's context
        self._note_request(parent, child)
        parent.children += 1
        sess.recent_spawns.append(now)
        self._emit(session_id, kind=EventKind.SPAWN, src_id=parent_id, src_role=parent.role, dst_id=child_id,
                   dst_role=child_role, dst_type=NodeType.AGENT, spawn_depth=parent.depth + 1,
                   privilege_tier=role.privilege_tier)
        return verdict

    def _send(self, session_id: str, src_id: str, dst_id: str, *, token_count: int | None,
              structured: bool) -> Verdict:
        t0 = time.perf_counter()
        sess = self._session(session_id)
        src = self._agent(sess, src_id)
        dst = self._agent(sess, dst_id)
        verdict = self.policy.check_message(src)
        if not verdict.allowed:
            self._gate(session_id, src, dst_id, verdict, t0)
            return verdict
        self._emit(session_id, kind=EventKind.MSG_SEND, src_id=src_id, src_role=src.role, dst_id=dst_id,
                   dst_type=NodeType.AGENT, token_count=token_count, trust=src.trust, data_classes=set(src.labels),
                   reason="structured" if structured else None)
        if structured:
            self._absorb(dst, Trust.INTERNAL, src.labels)
        else:
            self._absorb(dst, src.trust, src.labels)
            self._note_request(src, dst)
        return verdict

    def reset_context(self, session_id: str, agent_id: str, reason: str = "task boundary") -> None:
        """Called by the (trusted) agent runtime when it really clears an agent's context."""
        agent = self._agent(self._session(session_id), agent_id)
        agent.trust, agent.labels = Trust.SYSTEM, set()
        agent.untrusted_requests.clear()
        self._emit(session_id, kind=EventKind.CONTEXT_RESET, src_id=agent_id, src_role=agent.role, reason=reason)

    def _call_tool(self, session_id: str, agent_id: str, tool_name: str, args: dict | None) -> ToolResponse:
        t0 = time.perf_counter()
        args = args or {}
        sess = self._session(session_id)
        agent = self._agent(sess, agent_id)
        tool = self.registry.tools.get(tool_name)
        h = args_hash(tool_name, args)
        now = self.clock()
        sensitivity = self.registry.effective_sensitivity(tool, args) if tool else None

        self._emit(session_id, kind=EventKind.TOOL_CALL, src_id=agent_id, src_role=agent.role,
                   privilege_tier=agent.privilege_tier, dst_id=tool_name, dst_type=NodeType.TOOL,
                   side_effect=tool.side_effect if tool else None, sensitivity=sensitivity, args_hash=h,
                   trust=agent.trust, data_classes=set(agent.labels))
        verdict = self.policy.check_tool(sess, agent, tool, tool_name, args, h, now)
        if verdict.decision == "approve_required" and self.approver and self.approver(agent, tool_name, args, verdict):
            verdict = Verdict("allow", verdict.rule, f"approved: {verdict.reason}")
        self._gate(session_id, agent, tool_name, verdict, t0)
        if not verdict.allowed:
            return ToolResponse(False, verdict.rule, verdict.reason)

        agent.recent_calls.append((now, h))
        output = self.executor(tool_name, args)
        store = self.registry.store_for(tool, args)
        classes = set(tool.output_classes)
        if store is not None:
            classes |= store.data_classes
            self._emit(session_id, kind=EventKind.DATA_ACCESS, src_id=tool_name, dst_id=store.name,
                       dst_type=NodeType.STORE, resource_uri=f"store://{store.name}", op=output.op,
                       row_volume=output.rows, data_classes=set(store.data_classes))
        self._emit(session_id, kind=EventKind.TOOL_RESULT, src_id=agent_id, src_role=agent.role, dst_id=tool_name,
                   dst_type=NodeType.TOOL, status=output.status, trust=tool.output_trust, data_classes=classes,
                   row_volume=output.rows)
        self._absorb(agent, tool.output_trust, classes)
        return ToolResponse(True, output=output)

    # ---- control plane ------------------------------------------------------

    def agent_tier(self, session_id: str, agent_id: str) -> Tier | None:
        sess = self.sessions.get(session_id)
        agent = sess.agents.get(agent_id) if sess else None
        return agent.tier if agent else None

    def set_tier(self, session_id: str, agent_id: str, tier: Tier, reason: str) -> None:
        sess = self._session(session_id)
        agent = self._agent(sess, agent_id)
        agent.tier = tier
        self._emit(session_id, kind=EventKind.TIER_CHANGE, src_id=agent_id, src_role=agent.role, tier=tier,
                   reason=reason)

    # ---- metrics ------------------------------------------------------------

    def event_count(self, session_id: str) -> int:
        """Events emitted so far in a session; the next event's index."""
        return self._event_counter.get(session_id, 0)

    def latency_percentile(self, q: float) -> float | None:
        if not self.gate_latency_ms:
            return None
        xs = sorted(self.gate_latency_ms)
        return xs[min(len(xs) - 1, int(q * len(xs)))]

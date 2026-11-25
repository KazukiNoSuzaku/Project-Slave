"""Dashboard read model.

`DashboardState` folds the gateway event stream into what the Ops Terminal UI
shows: KPIs, per-session agent trees with taint labels, the alert log, rule-hit
counters and gate latency. It is pure (no I/O) so the same class can consume the
demo feed today and the real event bus later.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from slave.schema import Event, EventKind, Tier, Trust

ACTIVE_WINDOW = timedelta(minutes=5)
DENIAL_WINDOW = timedelta(hours=1)
LOG_MAXLEN = 500
LATENCY_SAMPLES = 1000
MAX_SESSIONS = 200
SNAPSHOT_SESSIONS = 20


@dataclass
class ToolUse:
    count: int = 0
    denied: int = 0
    last_rule: str | None = None


@dataclass
class AgentView:
    agent_id: str
    role: str | None = None
    parent: str | None = None
    tier: Tier = Tier.NORMAL
    taint: set[str] = field(default_factory=set)
    last_p_star: float | None = None
    tools: dict[str, ToolUse] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id,
            "role": self.role,
            "parent": self.parent,
            "tier": int(self.tier),
            "taint": sorted(self.taint),
            "p_star": self.last_p_star,
            "tools": [
                {"tool": name, "count": u.count, "denied": u.denied, "rule": u.last_rule}
                for name, u in sorted(self.tools.items())
            ],
        }


@dataclass
class SessionView:
    session_id: str
    last_seen: datetime
    agents: dict[str, AgentView] = field(default_factory=dict)
    messages: Counter = field(default_factory=Counter)
    log: list[dict[str, Any]] = field(default_factory=list)

    def agent(self, agent_id: str) -> AgentView:
        if agent_id not in self.agents:
            self.agents[agent_id] = AgentView(agent_id)
        return self.agents[agent_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.session_id,
            "last_seen": self.last_seen.isoformat(),
            "agents": [a.to_dict() for a in self.agents.values()],
            "messages": [{"src": s, "dst": d, "count": c} for (s, d), c in self.messages.items()],
            "max_tier": max((int(a.tier) for a in self.agents.values()), default=0),
        }


def _taint_labels(event: Event) -> set[str]:
    labels = set(event.data_classes)
    if event.trust is Trust.UNTRUSTED:
        labels.add("untrusted")
    return labels


class DashboardState:
    def __init__(self) -> None:
        self.sessions: dict[str, SessionView] = {}
        self.log: deque[dict[str, Any]] = deque(maxlen=LOG_MAXLEN)
        self.denials: deque[datetime] = deque()
        self.gate_latency: deque[float] = deque(maxlen=LATENCY_SAMPLES)
        self.rule_hits: Counter = Counter()
        self.incidents: deque[dict[str, Any]] = deque(maxlen=200)
        self.event_count = 0
        self.now: datetime | None = None

    # ---- ingest -------------------------------------------------------------

    def apply(self, event: Event) -> list[dict[str, Any]]:
        """Fold one event into state. Returns the log lines it produced."""
        self.event_count += 1
        self.now = event.ts
        sess = self.sessions.get(event.session_id)
        if sess is None:
            if len(self.sessions) >= MAX_SESSIONS:
                oldest = min(self.sessions.values(), key=lambda s: s.last_seen)
                del self.sessions[oldest.session_id]
            sess = self.sessions[event.session_id] = SessionView(event.session_id, event.ts)
        sess.last_seen = event.ts

        lines: list[dict[str, Any]] = []

        def emit(level: str, msg: str) -> None:
            line = {"ts": event.ts.isoformat(), "level": level, "session": event.session_id, "msg": msg}
            lines.append(line)

        gateway_sourced = event.kind in (EventKind.DATA_ACCESS, EventKind.NOTICE, EventKind.COMPENSATE)
        src = None if gateway_sourced else sess.agent(event.src_id)
        if src is not None and event.src_role and not src.role:
            src.role = event.src_role

        match event.kind:
            case EventKind.SPAWN:
                assert event.dst_id is not None
                child = sess.agent(event.dst_id)
                child.parent = event.src_id
                child.role = child.role or event.dst_role
                child.taint |= src.taint  # child inherits parent context labels
                emit("INFO", f"SPAWN {event.src_id} → {event.dst_id}")
            case EventKind.MSG_SEND:
                assert event.dst_id is not None
                dst = sess.agent(event.dst_id)
                dst.taint |= src.taint
                sess.messages[(event.src_id, event.dst_id)] += 1
            case EventKind.TOOL_CALL:
                assert event.dst_id is not None
                src.tools.setdefault(event.dst_id, ToolUse()).count += 1
            case EventKind.TOOL_RESULT:
                new = _taint_labels(event) - src.taint
                if new:
                    src.taint |= new
                    emit("INFO", f"taint {event.src_id} += {','.join(sorted(new))} ({event.dst_id})")
            case EventKind.GATE_DECISION:
                if event.latency_ms is not None:
                    self.gate_latency.append(event.latency_ms)
                if event.decision in ("deny", "approve_required"):
                    use = src.tools.setdefault(event.dst_id or "?", ToolUse())
                    use.denied += 1
                    use.last_rule = event.rule
                    self.denials.append(event.ts)
                    if event.rule:
                        self.rule_hits[event.rule] += 1
                    level = "DENY" if event.decision == "deny" else "HOLD"  # HOLD = awaiting human approval
                    emit(level, f"{event.rule or 'policy'} {event.src_id} {event.dst_id}"
                         + (f" — {event.reason}" if event.reason else ""))
            case EventKind.SCORE:
                src.last_p_star = event.p_star
                if event.p_star is not None and event.p_star < 1e-2:
                    emit("SCORE", f"{event.src_id} p*={event.p_star:.1e}"
                         + (f" {event.reason}" if event.reason else ""))
            case EventKind.TIER_CHANGE:
                assert event.tier is not None
                src.tier = event.tier
                verb = {
                    Tier.NORMAL: "restored",
                    Tier.ELEVATED: "elevated",
                    Tier.CONSTRAINED: "constrained",
                    Tier.QUARANTINED: "QUARANTINED",
                }[event.tier]
                emit(f"TIER{int(event.tier)}", f"{event.src_id} {verb}"
                     + (f" — {event.reason}" if event.reason else ""))
            case EventKind.TERMINATE:
                emit("INFO", f"TERMINATE {event.src_id}" + (f" ({event.reason})" if event.reason else ""))
            case EventKind.INCIDENT:
                self.incidents.append({"ts": event.ts.isoformat(), "session": event.session_id,
                                       "agent": event.src_id, "summary": event.reason})
                emit("INCDT", event.reason or f"incident on {event.src_id}")
            case EventKind.NOTICE:
                emit("NOTE", f"→ {event.dst_id}: {event.reason}")
            case EventKind.COMPENSATE:
                emit("UNDO", event.reason or f"compensation {event.dst_id}")
            case EventKind.CONTEXT_RESET:
                src.taint.clear()
                emit("INFO", f"context reset {event.src_id} ({event.reason})")
            case EventKind.DATA_ACCESS:
                pass

        self.log.extend(lines)
        sess.log.extend(lines)
        return lines

    # ---- read model ---------------------------------------------------------

    def _prune(self) -> None:
        if self.now is None:
            return
        while self.denials and self.now - self.denials[0] > DENIAL_WINDOW:
            self.denials.popleft()

    def gate_p99(self) -> float | None:
        if not self.gate_latency:
            return None
        xs = sorted(self.gate_latency)
        return xs[min(len(xs) - 1, int(0.99 * len(xs)))]

    def active_sessions(self) -> list[SessionView]:
        if self.now is None:
            return []
        return [s for s in self.sessions.values() if self.now - s.last_seen <= ACTIVE_WINDOW]

    def quarantined(self) -> list[dict[str, str]]:
        return [
            {"session": s.session_id, "agent": a.agent_id}
            for s in self.sessions.values()
            for a in s.agents.values()
            if a.tier is Tier.QUARANTINED
        ]

    def kpis(self) -> dict[str, Any]:
        self._prune()
        active = self.active_sessions()
        return {
            "sessions": len(active),
            "agents": sum(len(s.agents) for s in active),
            "denials_1h": len(self.denials),
            "quarantined": len(self.quarantined()),
            "gate_p99_ms": self.gate_p99(),
            "events": self.event_count,
        }

    def snapshot(self, log_tail: int = 60) -> dict[str, Any]:
        sessions = sorted(self.sessions.values(), key=lambda s: s.last_seen, reverse=True)
        return {
            "kpis": self.kpis(),
            "quarantined": self.quarantined(),
            "rule_hits": dict(self.rule_hits),
            "incidents": list(self.incidents)[-20:],
            "sessions": [s.to_dict() for s in sessions[:SNAPSHOT_SESSIONS]],
            "log": list(self.log)[-log_tail:],
        }

    def session_log(self, session_id: str) -> list[dict[str, Any]]:
        sess = self.sessions.get(session_id)
        return list(sess.log) if sess else []

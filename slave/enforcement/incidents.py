"""Incidents, the compensation journal, and parent notices (design.md §8).

* Every allowed mutating or egress tool call is journaled.
* When an agent is quarantined, an `Incident` collects the journaled calls of
  the agent and its subtree from the last `window`. Each call becomes a
  `Proposal`: its registered compensating tool, or `None` if it can't be undone
  (an email that was sent, a service restart). Proposals run only after a
  human confirms them.
* The quarantined agent's parent receives a `Notice` (AGENT_QUARANTINED), so
  it can reroute or escalate instead of waiting for a reply that will never come.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from slave.registry import Registry

WINDOW = timedelta(minutes=5)


@dataclass(frozen=True)
class JournalEntry:
    event_id: str
    session_id: str
    agent_id: str
    tool: str
    args: dict[str, Any]
    ts: datetime


@dataclass
class Proposal:
    entry: JournalEntry
    compensation: str | None  # None → irreversible
    executed: bool = False

    @property
    def reversible(self) -> bool:
        return self.compensation is not None


@dataclass(frozen=True)
class Notice:
    kind: str  # AGENT_QUARANTINED | SESSION_FROZEN
    about: str  # agent the notice concerns
    reason: str
    incident_id: str
    safe_to_retry: bool  # True if the work can be retried by a fresh agent


@dataclass
class Incident:
    id: str
    session_id: str
    agent_id: str
    subtree: list[str]
    reason: str
    opened_at: datetime
    severity: Literal["quarantine", "page"]
    proposals: list[Proposal] = field(default_factory=list)
    status: Literal["open", "released", "confirmed"] = "open"
    resolved_by: str | None = None
    note: str | None = None

    @property
    def irreversible(self) -> list[JournalEntry]:
        return [p.entry for p in self.proposals if not p.reversible]

    def summary(self) -> str:
        rev = sum(p.reversible for p in self.proposals)
        irr = len(self.proposals) - rev
        scope = "session frozen" if self.severity == "page" else f"subtree {len(self.subtree)}"
        return f"{self.id} {self.agent_id}: {self.reason} ({scope}; {rev} reversible, {irr} irreversible)"


class Enforcer:
    def __init__(self, registry: Registry, window: timedelta = WINDOW) -> None:
        self.registry = registry
        self.window = window
        self.journal: dict[str, list[JournalEntry]] = defaultdict(list)
        self.incidents: dict[str, Incident] = {}
        self.inbox: dict[tuple[str, str], list[Notice]] = defaultdict(list)

    def record(self, entry: JournalEntry) -> None:
        self.journal[entry.session_id].append(entry)

    def open(self, session_id: str, agent_id: str, subtree: list[str], reason: str, now: datetime,
             severity: Literal["quarantine", "page"]) -> Incident:
        scope = {agent_id, *subtree}
        if severity == "page":  # frozen session: every agent's recent changes are suspect
            scope = {e.agent_id for e in self.journal.get(session_id, [])}
        entries = [e for e in self.journal.get(session_id, []) if e.agent_id in scope and now - e.ts <= self.window]
        inc = Incident(f"INC-{len(self.incidents) + 1:05d}", session_id, agent_id, subtree, reason, now, severity,
                       [Proposal(e, self.registry.tools[e.tool].compensation) for e in entries])
        self.incidents[inc.id] = inc
        return inc

    def notify(self, session_id: str, recipient: str, notice: Notice) -> None:
        self.inbox[(session_id, recipient)].append(notice)

    def notices(self, session_id: str, recipient: str) -> list[Notice]:
        return list(self.inbox.get((session_id, recipient), ()))

    def has_notice(self, session_id: str, recipient: str, about: str) -> bool:
        return any(n.about == about for n in self.inbox.get((session_id, recipient), ()))

    def open_for(self, session_id: str, agent_id: str) -> Incident | None:
        for inc in reversed(list(self.incidents.values())):
            if inc.session_id == session_id and inc.agent_id == agent_id and inc.status == "open":
                return inc
        return None

    def close_session(self, session_id: str) -> None:
        self.journal.pop(session_id, None)
        for key in [k for k in self.inbox if k[0] == session_id]:
            del self.inbox[key]

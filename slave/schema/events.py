"""Gateway event schema (design.md §3.1).

One `Event` per interaction the gateway sees (data plane) or per decision the
control plane makes (gate decision, score, tier change). Keeping both in one
stream lets the dashboard, the event store and the replay view share a single
ordered log.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class EventKind(str, Enum):
    # data plane
    MSG_SEND = "MSG_SEND"
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    DATA_ACCESS = "DATA_ACCESS"
    SPAWN = "SPAWN"
    TERMINATE = "TERMINATE"
    # control plane
    GATE_DECISION = "GATE_DECISION"
    SCORE = "SCORE"
    TIER_CHANGE = "TIER_CHANGE"


class NodeType(str, Enum):
    AGENT = "agent"
    TOOL = "tool"
    STORE = "store"


class SideEffect(str, Enum):
    READ_ONLY = "read_only"
    MUTATING = "mutating"
    EXTERNAL_EGRESS = "external_egress"


class Trust(str, Enum):
    SYSTEM = "system"
    INTERNAL = "internal"
    UNTRUSTED = "untrusted"


class Tier(IntEnum):
    NORMAL = 0
    ELEVATED = 1
    CONSTRAINED = 2
    QUARANTINED = 3


Decision = Literal["allow", "deny", "approve_required"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Event(BaseModel):
    event_id: str = Field(default_factory=lambda: uuid4().hex)
    session_id: str
    ts: datetime = Field(default_factory=_now)
    kind: EventKind

    src_id: str
    dst_id: str | None = None
    src_role: str | None = None
    dst_role: str | None = None
    dst_type: NodeType | None = None

    # tool / data metadata
    side_effect: SideEffect | None = None
    trust: Trust | None = None
    data_classes: set[str] = Field(default_factory=set)
    row_volume: int | None = None

    # control-plane fields
    decision: Decision | None = None
    rule: str | None = None
    latency_ms: float | None = None
    p_star: float | None = None
    tier: Tier | None = None
    reason: str | None = None

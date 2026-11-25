"""Gateway event schema (design.md §3.1).

One `Event` per interaction the gateway sees (data plane) or per decision the
control plane makes (gate decision, score, tier change). Keeping both in one
stream lets the dashboard, the event store and the replay view share a single
ordered log.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_serializer


class EventKind(str, Enum):
    # data plane
    MSG_SEND = "MSG_SEND"
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    DATA_ACCESS = "DATA_ACCESS"
    SPAWN = "SPAWN"
    TERMINATE = "TERMINATE"
    CONTEXT_RESET = "CONTEXT_RESET"  # runtime cleared an agent's context (provenance labels reset)
    # control plane
    GATE_DECISION = "GATE_DECISION"
    SCORE = "SCORE"
    TIER_CHANGE = "TIER_CHANGE"
    NOTICE = "NOTICE"  # synthetic message from the gateway, e.g. AGENT_QUARANTINED to the parent
    INCIDENT = "INCIDENT"  # incident opened on quarantine / session freeze
    COMPENSATE = "COMPENSATE"  # compensating action executed after human confirmation


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


TRUST_RANK = {Trust.UNTRUSTED: 0, Trust.INTERNAL: 1, Trust.SYSTEM: 2}


def join_trust(a: Trust, b: Trust) -> Trust:
    """Provenance join: a context is only as trusted as the least-trusted thing in it."""
    return a if TRUST_RANK[a] <= TRUST_RANK[b] else b


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

    # agent metadata (source agent unless noted)
    privilege_tier: int | None = None
    spawn_depth: int | None = None  # SPAWN: depth of the child

    # tool / data metadata
    side_effect: SideEffect | None = None
    sensitivity: int | None = None
    args_hash: str | None = None
    args: dict[str, Any] | None = None  # full call arguments, captured only for agents at Tier >= 1
    status: Literal["ok", "error"] | None = None
    # TOOL_RESULT: label of the output. TOOL_CALL / MSG_SEND: the caller's
    # context label at the time of the action.
    trust: Trust | None = None
    data_classes: set[str] = Field(default_factory=set)
    resource_uri: str | None = None
    op: str | None = None
    row_volume: int | None = None
    token_count: int | None = None

    # control-plane fields
    decision: Decision | None = None
    rule: str | None = None
    latency_ms: float | None = None
    p_star: float | None = None
    tier: Tier | None = None
    reason: str | None = None

    # set by the event store when the event is sealed into the hash chain
    seq: int | None = None
    prev_hash: str | None = None
    hash: str | None = None

    @field_serializer("data_classes")
    def _sorted_classes(self, v: set[str]) -> list[str]:
        # sets have no stable order; hashing needs one
        return sorted(v)

    def canonical_json(self) -> str:
        """Deterministic JSON of the event content (chain fields excluded)."""
        body = self.model_dump(mode="json", exclude=CHAIN_FIELDS, exclude_none=True)
        return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


CHAIN_FIELDS = {"seq", "prev_hash", "hash"}

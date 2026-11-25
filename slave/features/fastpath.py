"""Fast-path behavioural features (design.md §5).

`FeatureExtractor` consumes the gateway event stream and, for every *scored*
event — an agent's TOOL_CALL, MSG_SEND or SPAWN — returns a feature vector
describing that agent's behaviour at that moment. State is incremental and
per session; nothing is recomputed from history.

Each scored event is first turned into an *action token*: `tool:<name>`,
`msg:<peer role>` or `spawn:<child role>`. `Baseline` learns, from benign
traffic only, per-role action-transition counts (with smoothing and backoff),
per-role action distributions and per-role maximum call sensitivity.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from slave.schema import Event, EventKind, Trust

START = "<start>"
SCORED = {EventKind.TOOL_CALL, EventKind.MSG_SEND, EventKind.SPAWN}
MINUTE = timedelta(minutes=1)
PINGPONG_WINDOW = timedelta(minutes=2)
ACTION_WINDOW = 20  # actions kept for entropy / KL

FEATURES = [
    "trans_surprisal", "trans_unseen", "action_unseen", "win_entropy", "win_kl",
    "pingpong", "identical_repeats", "actions_per_min", "msgs_per_min", "spawn_depth",
    "session_spawns_per_min", "sens_over_role_max", "session_sensitive_stores", "session_pii_rows",
    "session_msgs", "untrusted", "holds_pii", "agent_blocks", "gap_s",
]


# ---- baseline -----------------------------------------------------------------

@dataclass
class Baseline:
    """Benign behaviour statistics; fit once on training traffic, then frozen."""

    alpha: float = 0.1
    min_context: int = 20
    surprisal_cap: float = 12.0
    trans_role: Counter = field(default_factory=Counter)  # (role, prev, tok)
    ctx_role: Counter = field(default_factory=Counter)  # (role, prev)
    trans_any: Counter = field(default_factory=Counter)  # (prev, tok)
    ctx_any: Counter = field(default_factory=Counter)  # prev
    tok_role: Counter = field(default_factory=Counter)  # (role, tok)
    n_role: Counter = field(default_factory=Counter)  # role
    vocab: set[str] = field(default_factory=set)
    role_max_sens: dict[str, int] = field(default_factory=dict)

    def observe(self, role: str, prev: str, tok: str, sensitivity: int | None) -> None:
        self.trans_role[(role, prev, tok)] += 1
        self.ctx_role[(role, prev)] += 1
        self.trans_any[(prev, tok)] += 1
        self.ctx_any[prev] += 1
        self.tok_role[(role, tok)] += 1
        self.n_role[role] += 1
        self.vocab.add(tok)
        if sensitivity is not None:
            self.role_max_sens[role] = max(self.role_max_sens.get(role, 0), sensitivity)

    def fit(self, events: Iterable[Event]) -> Baseline:
        tracker = _TokenTracker()
        for ev in events:
            if (step := tracker.step(ev)) is not None:
                role, prev, tok = step
                self.observe(role, prev, tok, ev.sensitivity if ev.kind is EventKind.TOOL_CALL else None)
        return self

    def surprisal(self, role: str, prev: str, tok: str) -> float:
        """-log P(tok | prev, role), additive smoothing, backing off when context is thin."""
        v = max(len(self.vocab), 1) + 1  # +1 for unseen tokens
        a = self.alpha
        if self.ctx_role[(role, prev)] >= self.min_context:
            p = (self.trans_role[(role, prev, tok)] + a) / (self.ctx_role[(role, prev)] + a * v)
        elif self.ctx_any[prev] >= self.min_context:
            p = (self.trans_any[(prev, tok)] + a) / (self.ctx_any[prev] + a * v)
        else:
            p = (self.tok_role[(role, tok)] + a) / (self.n_role[role] + a * v)
        return min(-math.log(p), self.surprisal_cap)

    def role_dist(self, role: str) -> dict[str, float]:
        n = self.n_role[role]
        v = max(len(self.vocab), 1) + 1
        return {tok: (self.tok_role[(role, tok)] + self.alpha) / (n + self.alpha * v) for tok in self.vocab} | {
            "<unk>": self.alpha / (n + self.alpha * v)}


class _TokenTracker:
    """Maps events to (role, prev_token, token) per agent. Shared by Baseline and FeatureExtractor."""

    def __init__(self) -> None:
        self.roles: dict[tuple[str, str], str] = {}
        self.prev: dict[tuple[str, str], str] = {}

    def token(self, ev: Event) -> str | None:
        sid = ev.session_id
        if ev.kind is EventKind.TOOL_CALL:
            return f"tool:{ev.dst_id}"
        if ev.kind is EventKind.MSG_SEND:
            return f"msg:{self.roles.get((sid, ev.dst_id or ''), '?')}"
        if ev.kind is EventKind.SPAWN:
            return f"spawn:{ev.dst_role}"
        return None

    def step(self, ev: Event) -> tuple[str, str, str] | None:
        sid = ev.session_id
        if ev.kind is EventKind.SPAWN and ev.dst_id and ev.dst_role:
            self.roles[(sid, ev.dst_id)] = ev.dst_role
        if ev.kind is EventKind.TERMINATE:
            self.prev.pop((sid, ev.src_id), None)
            self.roles.pop((sid, ev.src_id), None)
            return None
        if ev.kind not in SCORED:
            return None
        role = self.roles.get((sid, ev.src_id))
        if role is None:  # e.g. the session opener ("user")
            return None
        tok = self.token(ev)
        assert tok is not None
        prev = self.prev.get((sid, ev.src_id), START)
        self.prev[(sid, ev.src_id)] = tok
        return role, prev, tok


# ---- extractor ----------------------------------------------------------------

@dataclass
class _Agent:
    role: str
    depth: int = 0
    last_ts: datetime | None = None
    actions: deque[str] = field(default_factory=lambda: deque(maxlen=ACTION_WINDOW))
    action_ts: deque[datetime] = field(default_factory=deque)
    msg_ts: deque[datetime] = field(default_factory=deque)
    sent: deque[tuple[datetime, str]] = field(default_factory=deque)
    recv: deque[tuple[datetime, str]] = field(default_factory=deque)
    calls: deque[tuple[datetime, str]] = field(default_factory=deque)
    blocks: int = 0


@dataclass
class _Session:
    agents: dict[str, _Agent] = field(default_factory=dict)
    spawn_ts: deque[datetime] = field(default_factory=deque)
    sensitive_stores: set[str] = field(default_factory=set)
    pii_rows: int = 0
    msgs: int = 0
    root: str | None = None


def _trim(dq: deque, now: datetime, window: timedelta, key=lambda x: x) -> None:
    while dq and now - key(dq[0]) > window:
        dq.popleft()


def _entropy(counts: Counter) -> float:
    n = sum(counts.values())
    return -sum(c / n * math.log2(c / n) for c in counts.values()) if n else 0.0


@dataclass(frozen=True)
class Scored:
    session_id: str
    agent_id: str
    role: str
    idx: int
    features: dict[str, float]


class FeatureExtractor:
    def __init__(self, baseline: Baseline) -> None:
        self.baseline = baseline
        self.tracker = _TokenTracker()
        self.sessions: dict[str, _Session] = defaultdict(_Session)
        self._role_dists: dict[str, dict[str, float]] = {}

    def _role_dist(self, role: str) -> dict[str, float]:
        if role not in self._role_dists:
            self._role_dists[role] = self.baseline.role_dist(role)
        return self._role_dists[role]

    def process(self, ev: Event) -> Scored | None:
        sess = self.sessions[ev.session_id]
        now = ev.ts

        # --- bookkeeping for non-scored events
        if ev.kind is EventKind.SPAWN and ev.dst_id and ev.dst_role:
            sess.agents[ev.dst_id] = _Agent(ev.dst_role, depth=ev.spawn_depth or 0)
            if ev.src_id not in sess.agents:
                sess.root = ev.dst_id
        elif ev.kind is EventKind.DATA_ACCESS:
            if ev.data_classes & {"pii", "restricted"} and ev.dst_id:
                sess.sensitive_stores.add(ev.dst_id)
                sess.pii_rows += ev.row_volume or 0
        elif ev.kind is EventKind.GATE_DECISION and ev.decision != "allow":
            if (a := sess.agents.get(ev.src_id)):
                a.blocks += 1
        elif ev.kind is EventKind.MSG_SEND and ev.dst_id in sess.agents:
            sess.agents[ev.dst_id].recv.append((now, ev.src_id))
        elif ev.kind is EventKind.TERMINATE and ev.src_id == sess.root:
            self.tracker.step(ev)
            self.sessions.pop(ev.session_id, None)
            return None

        step = self.tracker.step(ev)
        if step is None:
            return None
        role, prev, tok = step
        agent = sess.agents.get(ev.src_id)
        if agent is None:
            return None

        # --- windows
        agent.actions.append(tok)
        agent.action_ts.append(now)
        _trim(agent.action_ts, now, MINUTE)
        if ev.kind is EventKind.MSG_SEND:
            sess.msgs += 1
            agent.msg_ts.append(now)
            agent.sent.append((now, ev.dst_id or ""))
        _trim(agent.msg_ts, now, MINUTE)
        _trim(agent.sent, now, PINGPONG_WINDOW, key=lambda x: x[0])
        _trim(agent.recv, now, PINGPONG_WINDOW, key=lambda x: x[0])
        if ev.kind is EventKind.SPAWN:
            sess.spawn_ts.append(now)
        _trim(sess.spawn_ts, now, MINUTE)
        repeats = 0
        if ev.kind is EventKind.TOOL_CALL:
            _trim(agent.calls, now, MINUTE, key=lambda x: x[0])
            repeats = sum(1 for _, h in agent.calls if h == ev.args_hash)
            agent.calls.append((now, ev.args_hash or ""))

        sent_to = Counter(p for _, p in agent.sent)
        recv_from = Counter(p for _, p in agent.recv)
        pingpong = max((min(n, recv_from[p]) for p, n in sent_to.items()), default=0)

        window = Counter(agent.actions)
        base = self._role_dist(role)
        unk = base["<unk>"]
        n = sum(window.values())
        kl = sum(c / n * math.log((c / n) / base.get(t, unk)) for t, c in window.items())

        b = self.baseline
        sens_over = 0.0
        if ev.kind is EventKind.TOOL_CALL and ev.sensitivity is not None:
            sens_over = float(max(0, ev.sensitivity - b.role_max_sens.get(role, 0)))
        gap = (now - agent.last_ts).total_seconds() if agent.last_ts else 0.0
        agent.last_ts = now

        f = {
            "trans_surprisal": b.surprisal(role, prev, tok),
            "trans_unseen": float(b.trans_role[(role, prev, tok)] == 0),
            "action_unseen": float(b.tok_role[(role, tok)] == 0),
            "win_entropy": _entropy(window),
            "win_kl": kl,
            "pingpong": math.log1p(pingpong),
            "identical_repeats": math.log1p(repeats),
            "actions_per_min": math.log1p(len(agent.action_ts)),
            "msgs_per_min": math.log1p(len(agent.msg_ts)),
            "spawn_depth": float(agent.depth),
            "session_spawns_per_min": math.log1p(len(sess.spawn_ts)),
            "sens_over_role_max": sens_over,
            "session_sensitive_stores": float(len(sess.sensitive_stores)),
            "session_pii_rows": math.log1p(sess.pii_rows),
            "session_msgs": math.log1p(sess.msgs),
            "untrusted": float(ev.trust is Trust.UNTRUSTED),
            "holds_pii": float(bool(ev.data_classes & {"pii", "restricted"})),
            "agent_blocks": math.log1p(agent.blocks),
            "gap_s": math.log1p(gap),
        }
        return Scored(ev.session_id, ev.src_id, role, int(ev.event_id.rsplit(":", 1)[1]), f)

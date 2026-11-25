"""Windowed session snapshots for the deep path (design.md §4).

`SessionGraphs` consumes the event stream and, on request, turns the last
`window` of a session's events into a typed directed multigraph `Snapshot`:

* nodes: agents, tools and data stores seen in the window;
* edges: MSG_SEND / SPAWN (agent → agent), TOOL_CALL (agent → tool) and
  DATA_ACCESS (tool → store). Repeated interactions between the same pair are
  collapsed into one edge **with a count**, plus aggregated attributes;
* first/last relative timestamps on each edge keep some ordering.

`Snapshot.to_hetero()` produces a PyG `HeteroData`, adding a reverse relation
for every forward relation so information flows both ways while direction stays
distinguishable. `session_aggregates=True` (ablation v2a) appends whole-session
running totals to agent features.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import torch
from torch_geometric.data import HeteroData

from slave.registry import Registry, default_registry
from slave.schema import Event, EventKind, SideEffect, Trust

WINDOW = timedelta(minutes=5)
ROLES = ["planner", "researcher", "coder", "reviewer", "data_analyst", "ops"]
CLASSIFICATIONS = ["public", "internal", "pii", "restricted"]
SIDE_EFFECTS = [SideEffect.READ_ONLY, SideEffect.MUTATING, SideEffect.EXTERNAL_EGRESS]

# forward relations: (src type, name, dst type) and their edge-attribute width
RELATIONS = {
    ("agent", "msg", "agent"): 5,
    ("agent", "spawn", "agent"): 2,
    ("agent", "call", "tool"): 6,
    ("tool", "access", "store"): 5,
}
AGENT_BASE_DIM = len(ROLES) + 11
SESSION_AGG_DIM = 5
TOOL_DIM_EXTRA = 6  # + one-hot over tool names (registry dependent)
STORE_DIM = len(CLASSIFICATIONS) + 4


def rev(rel: tuple[str, str, str]) -> tuple[str, str, str]:
    return (rel[2], f"rev_{rel[1]}", rel[0])


def _log(x: float) -> float:
    return math.log1p(max(x, 0.0))


@dataclass
class _EdgeAgg:
    count: int = 0
    first: datetime | None = None
    last: datetime | None = None
    sum_a: float = 0.0  # tokens / rows
    flag_a: int = 0  # untrusted / write / error
    flag_b: int = 0  # denied
    depth: int = 0

    def hit(self, ts: datetime) -> None:
        self.count += 1
        self.first = self.first or ts
        self.last = ts


@dataclass
class Snapshot:
    session_id: str
    at: datetime
    agents: list[str]
    agent_roles: list[str]
    x: dict[str, list[list[float]]]
    edges: dict[tuple[str, str, str], tuple[list[tuple[int, int]], list[list[float]]]]
    dims: dict[str, int]

    def to_hetero(self) -> HeteroData:
        data = HeteroData()
        for t, rows in self.x.items():
            data[t].x = torch.tensor(rows, dtype=torch.float32).reshape(-1, self.dims[t])
        for rel, dim in RELATIONS.items():
            pairs, attrs = self.edges.get(rel, ([], []))
            ei = torch.tensor(pairs, dtype=torch.long).t().reshape(2, -1)
            ea = torch.tensor(attrs, dtype=torch.float32).reshape(-1, dim)
            data[rel].edge_index, data[rel].edge_attr = ei, ea
            data[rev(rel)].edge_index, data[rev(rel)].edge_attr = ei.flip(0), ea
        return data


@dataclass
class _SessionAgg:
    sensitive_stores: set[str] = field(default_factory=set)
    pii_rows: int = 0
    msgs: int = 0
    tools: set[str] = field(default_factory=set)
    start: datetime | None = None


class SessionGraphs:
    def __init__(self, registry: Registry | None = None, *, window: timedelta = WINDOW,
                 session_aggregates: bool = False) -> None:
        self.registry = registry or default_registry()
        self.tool_names = sorted(self.registry.tools) + ["spawn_agent"]
        self.window = window
        self.session_aggregates = session_aggregates
        self.events: dict[str, deque[Event]] = defaultdict(deque)
        self.roles: dict[str, dict[str, str]] = defaultdict(dict)
        self.depth: dict[str, dict[str, int]] = defaultdict(dict)
        self.agg: dict[str, _SessionAgg] = defaultdict(_SessionAgg)
        self.root: dict[str, str] = {}

    @property
    def dims(self) -> dict[str, int]:
        agent = AGENT_BASE_DIM + (SESSION_AGG_DIM if self.session_aggregates else 0)
        return {"agent": agent, "tool": TOOL_DIM_EXTRA + len(self.tool_names), "store": STORE_DIM}

    # ---- ingest -------------------------------------------------------------

    def add(self, ev: Event) -> None:
        sid = ev.session_id
        agg = self.agg[sid]
        agg.start = agg.start or ev.ts
        if ev.kind is EventKind.SPAWN and ev.dst_id and ev.dst_role:
            self.roles[sid][ev.dst_id] = ev.dst_role
            self.depth[sid][ev.dst_id] = ev.spawn_depth or 0
            if ev.src_id not in self.roles[sid]:
                self.root[sid] = ev.dst_id
        if ev.kind is EventKind.TERMINATE and self.root.get(sid) == ev.src_id:
            self.drop(sid)
            return
        if ev.kind is EventKind.DATA_ACCESS and ev.data_classes & {"pii", "restricted"} and ev.dst_id:
            agg.sensitive_stores.add(ev.dst_id)
            agg.pii_rows += ev.row_volume or 0
        if ev.kind is EventKind.MSG_SEND:
            agg.msgs += 1
        if ev.kind is EventKind.TOOL_CALL and ev.dst_id:
            agg.tools.add(ev.dst_id)
        if ev.kind in (EventKind.MSG_SEND, EventKind.SPAWN, EventKind.TOOL_CALL, EventKind.TOOL_RESULT,
                       EventKind.DATA_ACCESS, EventKind.GATE_DECISION):
            q = self.events[sid]
            q.append(ev)
            while q and ev.ts - q[0].ts > self.window:
                q.popleft()

    def drop(self, sid: str) -> None:
        for d in (self.events, self.roles, self.depth, self.agg, self.root):
            d.pop(sid, None)

    # ---- snapshot -----------------------------------------------------------

    def snapshot(self, sid: str, at: datetime) -> Snapshot | None:
        evs = [e for e in self.events.get(sid, ()) if at - e.ts <= self.window]
        roles = self.roles.get(sid, {})
        if not evs:
            return None
        t0 = at - self.window
        span = self.window.total_seconds()
        rel_t = lambda ts: (ts - t0).total_seconds() / span  # noqa: E731

        agents: dict[str, int] = {}
        tools: dict[str, int] = {}
        stores: dict[str, int] = {}

        def node(d: dict[str, int], key: str) -> int:
            return d.setdefault(key, len(d))

        edges: dict[tuple, dict[tuple[int, int], _EdgeAgg]] = {r: defaultdict(_EdgeAgg) for r in RELATIONS}
        a_stats: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        t_stats: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        s_stats: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))

        for e in evs:
            if e.kind is EventKind.MSG_SEND and e.src_id in roles and e.dst_id in roles:
                agg = edges[("agent", "msg", "agent")][(node(agents, e.src_id), node(agents, e.dst_id))]
                agg.hit(e.ts)
                agg.sum_a += e.token_count or 0
                agg.flag_a += e.trust is Trust.UNTRUSTED
                a_stats[e.src_id]["msg_out"] += 1
                a_stats[e.dst_id]["msg_in"] += 1
                a_stats[e.src_id]["untrusted"] = max(a_stats[e.src_id]["untrusted"], e.trust is Trust.UNTRUSTED)
            elif e.kind is EventKind.SPAWN and e.src_id in roles and e.dst_id in roles:
                agg = edges[("agent", "spawn", "agent")][(node(agents, e.src_id), node(agents, e.dst_id))]
                agg.hit(e.ts)
                agg.depth = e.spawn_depth or 0
                a_stats[e.src_id]["spawn_out"] += 1
            elif e.kind is EventKind.TOOL_CALL and e.src_id in roles and e.dst_id:
                agg = edges[("agent", "call", "tool")][(node(agents, e.src_id), node(tools, e.dst_id))]
                agg.hit(e.ts)
                agg.flag_a += e.trust is Trust.UNTRUSTED
                a_stats[e.src_id]["calls"] += 1
                a_stats[e.src_id]["untrusted"] = max(a_stats[e.src_id]["untrusted"], e.trust is Trust.UNTRUSTED)
                a_stats[e.src_id]["pii"] = max(a_stats[e.src_id]["pii"], bool(e.data_classes & {"pii", "restricted"}))
                t_stats[e.dst_id]["calls"] += 1
                t_stats[e.dst_id]["sens"] = max(t_stats[e.dst_id]["sens"], e.sensitivity or 0)
            elif e.kind is EventKind.GATE_DECISION and e.decision != "allow" and e.src_id in roles:
                a_stats[e.src_id]["blocks"] += 1
                if e.dst_id in tools and e.src_id in agents:
                    edges[("agent", "call", "tool")][(agents[e.src_id], tools[e.dst_id])].flag_b += 1
            elif e.kind is EventKind.TOOL_RESULT and e.dst_id in tools and e.src_id in agents:
                agg = edges[("agent", "call", "tool")][(agents[e.src_id], tools[e.dst_id])]
                agg.sum_a += e.status == "error"
                t_stats[e.dst_id]["errors"] += e.status == "error"
                t_stats[e.dst_id]["untrusted_out"] = max(t_stats[e.dst_id]["untrusted_out"], e.trust is Trust.UNTRUSTED)
            elif e.kind is EventKind.DATA_ACCESS and e.src_id and e.dst_id:
                agg = edges[("tool", "access", "store")][(node(tools, e.src_id), node(stores, e.dst_id))]
                agg.hit(e.ts)
                agg.sum_a += e.row_volume or 0
                agg.flag_a += (e.op or "").upper() == "WRITE"
                key = "rows_w" if (e.op or "").upper() == "WRITE" else "rows_r"
                s_stats[e.dst_id][key] += e.row_volume or 0
                s_stats[e.dst_id]["accesses"] += 1

        if not agents:
            return None

        # ---- node features
        agent_ids = sorted(agents, key=agents.get)
        sagg = self.agg.get(sid, _SessionAgg())
        x_agent = []
        for a in agent_ids:
            st = a_stats[a]
            role = roles.get(a, "")
            row = [float(role == r) for r in ROLES]
            priv = self.registry.roles[role].privilege_tier if role in self.registry.roles else 0
            row += [priv / 4, self.depth.get(sid, {}).get(a, 0) / 4, _log(st["msg_out"]), _log(st["msg_in"]),
                    _log(st["spawn_out"]), _log(st["calls"]), float(st["untrusted"]), float(st["pii"]),
                    _log(st["blocks"]), _log(st["msg_out"] + st["spawn_out"] + st["calls"]),
                    float(a == self.root.get(sid))]
            if self.session_aggregates:
                dur = (at - sagg.start).total_seconds() if sagg.start else 0.0
                row += [float(len(sagg.sensitive_stores)), _log(sagg.pii_rows), _log(sagg.msgs),
                        _log(len(sagg.tools)), _log(dur / 60)]
            x_agent.append(row)

        tool_ids = sorted(tools, key=tools.get)
        x_tool = []
        for t in tool_ids:
            st = t_stats[t]
            spec = self.registry.tools.get(t)
            row = [float(spec is not None and spec.side_effect is se) for se in SIDE_EFFECTS]
            row += [st["sens"] / 4, _log(st["calls"]), st["errors"] / max(st["calls"], 1)]
            row += [float(t == name) for name in self.tool_names]
            x_tool.append(row)

        store_ids = sorted(stores, key=stores.get)
        x_store = []
        for s in store_ids:
            st = s_stats[s]
            spec = self.registry.stores.get(s)
            row = [float(spec is not None and spec.classification == c) for c in CLASSIFICATIONS]
            row += [(spec.sensitivity if spec else 0) / 4, _log(st["rows_r"]), _log(st["rows_w"]),
                    _log(st["accesses"])]
            x_store.append(row)

        # ---- edge attributes
        out_edges = {}
        for rel, aggs in edges.items():
            pairs, attrs = [], []
            for (u, v), g in aggs.items():
                if g.count == 0:  # a denied call with no matching TOOL_CALL in window
                    continue
                first, last = rel_t(g.first), rel_t(g.last)
                if rel[1] == "msg":
                    a = [_log(g.count), _log(g.sum_a / g.count), first, last, g.flag_a / g.count]
                elif rel[1] == "spawn":
                    a = [g.depth / 4, first]
                elif rel[1] == "call":
                    a = [_log(g.count), g.sum_a / g.count, first, last, g.flag_a / g.count, g.flag_b / g.count]
                else:
                    a = [_log(g.count), _log(g.sum_a), first, last, g.flag_a / g.count]
                pairs.append((u, v))
                attrs.append(a)
            out_edges[rel] = (pairs, attrs)

        return Snapshot(sid, at, agent_ids, [roles.get(a, "") for a in agent_ids],
                        {"agent": x_agent, "tool": x_tool, "store": x_store}, out_edges, self.dims)

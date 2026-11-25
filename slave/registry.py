"""Static registry of roles, tools and data stores (design.md §1, §10).

The gateway's static policy is derived from this: which role may call which
tool, each role's privilege tier, and each tool's / store's sensitivity.
Sensitivity and privilege share a 0–4 scale; a call is allowed only when the
agent's privilege tier is at least the effective sensitivity of the call.
"""

from __future__ import annotations

from dataclasses import dataclass

from slave.schema import SideEffect, Trust


@dataclass(frozen=True)
class ToolSpec:
    name: str
    side_effect: SideEffect
    sensitivity: int
    output_trust: Trust
    output_classes: frozenset[str] = frozenset()
    uses_store: bool = False  # args["store"] names a DataStore


@dataclass(frozen=True)
class StoreSpec:
    name: str
    classification: str  # public | internal | pii | restricted
    sensitivity: int
    data_classes: frozenset[str] = frozenset()


@dataclass(frozen=True)
class RoleSpec:
    name: str
    privilege_tier: int
    tools: frozenset[str]
    can_spawn: bool = False


@dataclass(frozen=True)
class Registry:
    tools: dict[str, ToolSpec]
    stores: dict[str, StoreSpec]
    roles: dict[str, RoleSpec]

    def effective_sensitivity(self, tool: ToolSpec, args: dict) -> int:
        store = self.store_for(tool, args)
        return max(tool.sensitivity, store.sensitivity if store else 0)

    def store_for(self, tool: ToolSpec, args: dict) -> StoreSpec | None:
        if not tool.uses_store:
            return None
        return self.stores.get(str(args.get("store")))


_RO, _MUT, _EGR = SideEffect.READ_ONLY, SideEffect.MUTATING, SideEffect.EXTERNAL_EGRESS
_UNTRUSTED, _INTERNAL = Trust.UNTRUSTED, Trust.INTERNAL


def default_registry() -> Registry:
    tools = [
        ToolSpec("search", _RO, 0, _UNTRUSTED),
        ToolSpec("web_fetch", _RO, 0, _UNTRUSTED),
        ToolSpec("read_file", _RO, 1, _INTERNAL, uses_store=True),
        ToolSpec("write_file", _MUT, 2, _INTERNAL, uses_store=True),
        ToolSpec("git_diff", _RO, 1, _INTERNAL),
        ToolSpec("run_tests", _RO, 1, _INTERNAL),
        ToolSpec("git_commit", _MUT, 2, _INTERNAL),
        ToolSpec("sql_query", _RO, 2, _INTERNAL, uses_store=True),
        ToolSpec("read_logs", _RO, 1, _INTERNAL),
        ToolSpec("restart_service", _MUT, 3, _INTERNAL),
        ToolSpec("send_email", _EGR, 3, _INTERNAL),
        ToolSpec("http_post", _EGR, 3, _INTERNAL),
    ]
    stores = [
        StoreSpec("repo", "internal", 1),
        StoreSpec("docs", "internal", 1),
        StoreSpec("sales_db", "internal", 2),
        StoreSpec("customers_db", "pii", 3, frozenset({"pii"})),
        StoreSpec("hr_db", "restricted", 4, frozenset({"pii", "restricted"})),
    ]
    roles = [
        RoleSpec("planner", 2, frozenset({"read_file", "search"}), can_spawn=True),
        RoleSpec("researcher", 1, frozenset({"search", "web_fetch", "read_file"}), can_spawn=True),
        RoleSpec("coder", 2, frozenset({"read_file", "write_file", "git_diff", "run_tests", "git_commit"})),
        RoleSpec("reviewer", 2, frozenset({"read_file", "git_diff", "run_tests"})),
        RoleSpec("data_analyst", 3, frozenset({"sql_query", "read_file", "write_file"})),
        RoleSpec("ops", 3, frozenset({"read_logs", "restart_service", "send_email", "read_file"})),
    ]
    return Registry(
        tools={t.name: t for t in tools},
        stores={s.name: s for s in stores},
        roles={r.name: r for r in roles},
    )

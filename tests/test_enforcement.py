from datetime import datetime, timezone

import pytest

from slave.eval.phase5 import Chaos, run_chaos
from slave.gateway import Gateway, GatewayError, Policy, ProvenanceRules, ToolOutput
from slave.registry import default_registry
from slave.schema import Event, EventKind, Tier
from slave.sim.swarm import SimClock

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)


def make(notify: bool = True):
    events: list[Event] = []
    executed: list[tuple[str, dict]] = []
    reg = default_registry()

    def executor(tool, args):
        executed.append((tool, args))
        return ToolOutput(rows=1)

    gw = Gateway(reg, policy=Policy(reg, provenance=ProvenanceRules()), executor=executor,
                 sinks=[events.append], clock=SimClock(T0), notify_parent=notify)
    gw.open_session("s", "planner", "planner")
    gw.spawn("s", "planner", "res", "researcher")
    gw.spawn("s", "res", "sub", "researcher")
    gw.spawn("s", "sub", "subsub", "researcher")
    gw.spawn("s", "planner", "coder", "coder")
    return gw, events, executed


def kinds(events, k):
    return [e for e in events if e.kind is k]


def test_quarantine_terminates_subtree_notifies_parent_and_opens_incident():
    gw, events, _ = make()
    gw.set_tier("s", "res", Tier.QUARANTINED, "test")
    agents = gw.sessions["s"].agents
    assert agents["sub"].terminated and agents["subsub"].terminated
    assert not agents["coder"].terminated and not agents["planner"].terminated
    assert {e.src_id for e in kinds(events, EventKind.TERMINATE)} == {"sub", "subsub"}
    [notice] = gw.enforcer.notices("s", "planner")
    assert notice.kind == "AGENT_QUARANTINED" and notice.about == "res"
    [inc] = gw.enforcer.incidents.values()
    assert inc.severity == "quarantine" and set(inc.subtree) == {"sub", "subsub"}
    assert kinds(events, EventKind.NOTICE)[-1].dst_id == "planner"


def test_siblings_keep_working_and_sends_to_quarantined_fail_fast():
    gw, _, _ = make()
    gw.set_tier("s", "res", Tier.QUARANTINED, "test")
    assert gw.call_tool("s", "coder", "git_diff", {}).allowed  # sibling unaffected
    v = gw.send("s", "planner", "res")
    assert (v.allowed, v.rule) == (False, "DST_UNAVAILABLE")
    assert gw.call_tool("s", "sub", "search", {}).rule == "TERMINATED"
    resp = gw.call_tool("s", "res", "search", {})
    assert resp.rule == "T3" and resp.code == "POLICY_DENIED"


def test_quarantining_root_freezes_session_and_pages():
    gw, events, _ = make()
    gw.set_tier("s", "planner", Tier.QUARANTINED, "orchestrator compromised")
    sess = gw.sessions["s"]
    assert sess.frozen
    assert all(a.tier is Tier.QUARANTINED for a in sess.agents.values())
    assert gw.call_tool("s", "coder", "git_diff", {}).rule == "FROZEN"
    [notice] = gw.enforcer.notices("s", "human")
    assert notice.kind == "SESSION_FROZEN"
    [inc] = gw.enforcer.incidents.values()
    assert inc.severity == "page"


def test_parent_under_suspicion_also_freezes():
    gw, _, _ = make()
    gw.set_tier("s", "res", Tier.CONSTRAINED, "suspicious")
    gw.set_tier("s", "sub", Tier.QUARANTINED, "bad")  # parent `res` can't be trusted with the notice
    assert gw.sessions["s"].frozen


def test_journal_and_compensation_after_confirmation():
    gw, events, executed = make()
    gw.call_tool("s", "coder", "write_file", {"store": "repo", "path": "a.py"})
    gw.call_tool("s", "coder", "git_commit", {"message": "m"})
    gw.call_tool("s", "coder", "git_diff", {})  # read-only: not journaled
    gw.set_tier("s", "coder", Tier.QUARANTINED, "bad commit")
    [inc] = gw.enforcer.incidents.values()
    assert [(p.entry.tool, p.compensation) for p in inc.proposals] == [
        ("write_file", "restore_file"), ("git_commit", "git_revert")]
    call_ids = [e.event_id for e in kinds(events, EventKind.TOOL_CALL) if e.dst_id in ("write_file", "git_commit")]
    assert [p.entry.event_id for p in inc.proposals] == call_ids
    executed.clear()
    assert gw.confirm(inc.id, by="alice", undo_agents=["someone-else"]) == 0  # selective
    assert gw.confirm(inc.id, by="alice", undo_agents=["coder"]) == 2
    assert [t for t, _ in executed] == ["restore_file", "git_revert"]
    assert len(kinds(events, EventKind.COMPENSATE)) == 2 and inc.status == "confirmed"
    assert gw.confirm(inc.id, by="alice", undo_agents=["coder"]) == 0  # idempotent


def test_irreversible_actions_are_listed():
    gw, _, _ = make()
    gw.spawn("s", "planner", "ops", "ops")
    gw.call_tool("s", "ops", "send_email", {"to": "x"})
    gw.set_tier("s", "ops", Tier.QUARANTINED, "test")
    inc = gw.enforcer.open_for("s", "ops")
    assert [e.tool for e in inc.irreversible] == ["send_email"]
    assert gw.enforcer.notices("s", "planner")[0].safe_to_retry is False


def test_release_is_human_only_and_restores_agent():
    gw, events, _ = make()
    gw.set_tier("s", "coder", Tier.QUARANTINED, "fp")
    with pytest.raises(GatewayError):
        gw.set_tier("s", "coder", Tier.NORMAL, "scorer cooled down")
    inc = gw.release("s", "coder", by="bob", note="false positive")
    assert inc.status == "released" and inc.resolved_by == "bob"
    assert gw.call_tool("s", "coder", "git_diff", {}).allowed
    assert kinds(events, EventKind.TIER_CHANGE)[-1].reason.startswith("released by bob")


def test_release_unfreezes_session():
    gw, _, _ = make()
    gw.set_tier("s", "planner", Tier.QUARANTINED, "x")
    gw.release("s", "planner", by="bob")
    assert not gw.sessions["s"].frozen
    assert gw.call_tool("s", "coder", "git_diff", {}).allowed


def test_tier1_captures_payload_and_soft_rate_limits():
    gw, events, _ = make()
    gw.call_tool("s", "coder", "git_diff", {"path": "a"})
    assert kinds(events, EventKind.TOOL_CALL)[-1].args is None
    gw.set_tier("s", "coder", Tier.ELEVATED, "watch")
    gw.call_tool("s", "coder", "git_diff", {"path": "b"})
    assert kinds(events, EventKind.TOOL_CALL)[-1].args == {"path": "b"}
    for i in range(25):
        resp = gw.call_tool("s", "coder", "git_diff", {"path": str(i)})
    assert resp.rule == "P4" and "Tier 1" in resp.reason


def test_compensation_tools_are_not_callable_by_agents():
    gw, _, _ = make()
    assert gw.call_tool("s", "coder", "git_revert", {}).rule == "S1"


def test_chaos_negative_control():
    on = run_chaos("on", [1], 150, rate=0.5, notify=True)
    off = run_chaos("off", [1], 150, rate=0.5, notify=False)
    assert on.quarantines > 10 and on.quarantines == off.quarantines
    assert on.runtime["hangs"] == 0 and on.runtime["gateway_errors"] == 0 and on.collateral == 0
    assert off.runtime["hangs"] > 0
    assert on.open_sessions_left == 0


def test_chaos_controller_targets_non_root():
    gw, _, _ = make()
    chaos = Chaos(rate=1.0, seed=0)
    chaos.plan["s"] = 0
    chaos(gw, "s")
    target, _ = chaos.hits["s"]
    assert target != "planner" and gw.agent_tier("s", target) is Tier.QUARANTINED

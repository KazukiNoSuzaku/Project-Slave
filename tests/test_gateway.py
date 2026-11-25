from datetime import datetime, timedelta, timezone

import pytest

from slave.gateway import Caps, Gateway, GatewayError, Policy, ToolOutput
from slave.registry import default_registry
from slave.schema import Event, EventKind, Tier
from slave.sim.swarm import SimClock

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)


def make(caps: Caps | None = None):
    events: list[Event] = []
    clock = SimClock(T0)
    reg = default_registry()
    gw = Gateway(reg, policy=Policy(reg, caps), executor=lambda tool, args: ToolOutput(rows=3, op="SELECT"),
                 sinks=[events.append], clock=clock)
    gw.open_session("s", "planner-01", "planner")
    return gw, events, clock


def kinds(events):
    return [e.kind for e in events]


def test_allowed_call_emits_call_gate_access_result():
    gw, events, _ = make()
    gw.spawn("s", "planner-01", "analyst-02", "data_analyst")
    events.clear()
    resp = gw.call_tool("s", "analyst-02", "sql_query", {"store": "sales_db", "query": "q1"})
    assert resp.allowed and resp.output.rows == 3
    assert kinds(events) == [EventKind.TOOL_CALL, EventKind.GATE_DECISION, EventKind.DATA_ACCESS,
                             EventKind.TOOL_RESULT]
    call, gate, access, result = events
    assert call.sensitivity == 2 and call.args_hash
    assert gate.decision == "allow" and gate.latency_ms is not None
    assert access.dst_id == "sales_db" and access.row_volume == 3
    assert result.status == "ok"


def test_denied_call_never_executes():
    executed = []
    gw, events, _ = make()
    gw.executor = lambda tool, args: executed.append(tool) or ToolOutput()
    resp = gw.call_tool("s", "planner-01", "git_commit", {})
    assert not resp.allowed and resp.rule == "S1"
    assert executed == []
    assert kinds(events)[-2:] == [EventKind.TOOL_CALL, EventKind.GATE_DECISION]


def test_privilege_blocks_restricted_store():
    gw, _, _ = make()
    gw.spawn("s", "planner-01", "analyst-02", "data_analyst")
    resp = gw.call_tool("s", "analyst-02", "sql_query", {"store": "hr_db"})
    assert (resp.allowed, resp.rule) == (False, "S2")


def test_unknown_tool_and_store_denied():
    gw, _, _ = make()
    assert gw.call_tool("s", "planner-01", "rm_rf", {}).rule == "S1"
    assert gw.call_tool("s", "planner-01", "read_file", {"store": "nope"}).rule == "S1"


def test_tier_rules():
    gw, _, _ = make()
    gw.spawn("s", "planner-01", "coder-02", "coder")
    gw.set_tier("s", "coder-02", Tier.CONSTRAINED, "test")
    assert gw.call_tool("s", "coder-02", "git_commit", {}).rule == "T2"
    assert gw.call_tool("s", "coder-02", "git_diff", {}).allowed  # read-only still fine
    gw.set_tier("s", "coder-02", Tier.QUARANTINED, "test")
    assert gw.call_tool("s", "coder-02", "git_diff", {}).rule == "T3"
    assert gw.send("s", "coder-02", "planner-01").rule == "T3"


def test_spawn_caps():
    gw, _, _ = make(Caps(max_spawn_depth=2, max_children_per_agent=10))
    assert gw.spawn("s", "planner-01", "r1", "researcher").allowed
    assert gw.spawn("s", "r1", "r2", "researcher").allowed
    v = gw.spawn("s", "r2", "r3", "researcher")
    assert (v.allowed, v.rule) == (False, "P4")
    assert gw.spawn("s", "planner-01", "x", "coder").allowed
    assert gw.spawn("s", "x", "y", "coder").rule == "S1"  # coders can't spawn


def test_identical_call_cap_uses_window():
    gw, _, clock = make(Caps(max_identical_calls=3))
    gw.spawn("s", "planner-01", "c", "coder")
    for _ in range(3):
        assert gw.call_tool("s", "c", "run_tests", {"suite": "unit"}).allowed
    assert gw.call_tool("s", "c", "run_tests", {"suite": "unit"}).rule == "P4"
    assert gw.call_tool("s", "c", "run_tests", {"suite": "e2e"}).allowed  # different args
    clock.advance(61)
    assert gw.call_tool("s", "c", "run_tests", {"suite": "unit"}).allowed


def test_protocol_errors():
    gw, _, _ = make()
    with pytest.raises(GatewayError):
        gw.call_tool("nope", "planner-01", "search", {})
    with pytest.raises(GatewayError):
        gw.call_tool("s", "ghost", "search", {})
    with pytest.raises(GatewayError):
        gw.spawn("s", "planner-01", "planner-01", "coder")
    with pytest.raises(GatewayError):
        gw.open_session("s", "p", "planner")


def test_close_session_terminates_and_frees_state():
    gw, events, _ = make()
    gw.spawn("s", "planner-01", "c", "coder")
    gw.close_session("s")
    assert [e.src_id for e in events if e.kind is EventKind.TERMINATE] == ["c", "planner-01"]
    assert "s" not in gw.sessions


def test_event_ids_and_timestamps_follow_clock():
    gw, events, clock = make()
    clock.advance(5)
    gw.call_tool("s", "planner-01", "search", {"q": "x"})
    assert events[0].event_id == "s:000000"
    assert events[-1].ts == T0 + timedelta(seconds=5)

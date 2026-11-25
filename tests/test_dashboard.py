import json
import random
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from slave.dashboard.server import create_app
from slave.dashboard.state import DashboardState
from slave.schema import Event, EventKind, Tier, Trust
from slave.sim.demo_feed import build_cycle

BASE = datetime(2026, 11, 25, 10, 41, tzinfo=timezone.utc)


def ev(kind: EventKind, src: str, **kw) -> Event:
    return Event(session_id="sess-test", ts=BASE, kind=kind, src_id=src, **kw)


def test_taint_propagates_via_tool_result_message_and_spawn():
    st = DashboardState()
    st.apply(ev(EventKind.TOOL_RESULT, "research", dst_id="web_fetch", trust=Trust.UNTRUSTED))
    st.apply(ev(EventKind.MSG_SEND, "research", dst_id="planner"))
    st.apply(ev(EventKind.SPAWN, "planner", dst_id="child", dst_role="coder"))
    agents = st.sessions["sess-test"].agents
    assert agents["research"].taint == {"untrusted"}
    assert agents["planner"].taint == {"untrusted"}
    assert agents["child"].taint == {"untrusted"}
    assert agents["child"].parent == "planner"
    assert agents["child"].role == "coder"


def test_deny_counts_rule_hit_and_logs():
    st = DashboardState()
    st.apply(ev(EventKind.TOOL_CALL, "a", dst_id="sql_query"))
    lines = st.apply(ev(EventKind.GATE_DECISION, "a", dst_id="sql_query", decision="deny", rule="P1",
                        latency_ms=1.2))
    assert [l["level"] for l in lines] == ["DENY"]
    assert st.rule_hits["P1"] == 1
    assert st.kpis()["denials_1h"] == 1
    assert st.gate_p99() == 1.2
    tool = st.sessions["sess-test"].agents["a"].tools["sql_query"]
    assert (tool.count, tool.denied, tool.last_rule) == (1, 1, "P1")


def test_tier_change_tracks_quarantine():
    st = DashboardState()
    st.apply(ev(EventKind.TIER_CHANGE, "a", tier=Tier.QUARANTINED, reason="test"))
    assert st.quarantined() == [{"session": "sess-test", "agent": "a"}]
    assert st.snapshot()["sessions"][0]["max_tier"] == 3


def test_demo_cycle_hits_every_scenario():
    st = DashboardState()
    steps = build_cycle(random.Random(7), BASE)
    assert [s.at for s in steps] == sorted(s.at for s in steps)
    for step in steps:
        st.apply(step.event)
    snap = st.snapshot()
    assert len(snap["sessions"]) == 4
    assert snap["kpis"]["quarantined"] == 1
    assert st.rule_hits == {"P1": 1, "P4": 1}
    assert sorted(s["max_tier"] for s in snap["sessions"]) == [0, 1, 2, 3]
    json.dumps(snap)  # must be JSON-serialisable


def test_http_and_websocket():
    app = create_app(demo=False)
    with TestClient(app) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert "Ops Terminal" in client.get("/").text

        with client.websocket_connect("/ws") as ws:
            assert ws.receive_json()["type"] == "hello"
            body = json.loads(ev(EventKind.TIER_CHANGE, "x", tier=Tier.ELEVATED).model_dump_json())
            assert client.post("/api/events", json=body).json() == {"lines": 1}
            update = ws.receive_json()
            assert update["type"] == "update"
            assert update["lines"][0]["level"] == "TIER1"

        assert client.get("/api/sessions/sess-test/log").status_code == 200
        assert client.get("/api/sessions/nope/log").status_code == 404

from datetime import datetime, timezone

import pytest

from slave.eval.phase2 import RUNGS, render, run_rung, wilson
from slave.gateway import Gateway, Policy, ProvenanceRules, ToolOutput
from slave.registry import default_registry
from slave.schema import Event, EventKind, Tier, Trust
from slave.sim.attacks import ATTACKS
from slave.sim.swarm import SimClock, SimConfig, generate

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)


def make(rules: ProvenanceRules | None = ProvenanceRules(), approver=None):
    events: list[Event] = []
    reg = default_registry()
    gw = Gateway(reg, policy=Policy(reg, provenance=rules), executor=lambda t, a: ToolOutput(rows=1),
                 sinks=[events.append], clock=SimClock(T0), approver=approver)
    gw.open_session("s", "planner", "planner")
    return gw, events


def agent(gw, aid):
    return gw.sessions["s"].agents[aid]


def test_labels_propagate_through_result_message_and_spawn():
    gw, events = make()
    gw.spawn("s", "planner", "r", "researcher")
    gw.call_tool("s", "r", "web_fetch", {"url": "x"})
    assert agent(gw, "r").trust is Trust.UNTRUSTED
    gw.send("s", "r", "planner")
    assert agent(gw, "planner").trust is Trust.UNTRUSTED
    gw.spawn("s", "planner", "ops", "ops")
    assert agent(gw, "ops").trust is Trust.UNTRUSTED
    call = [e for e in events if e.kind is EventKind.TOOL_CALL][-1]
    assert call.trust is Trust.SYSTEM  # label recorded is the caller's context *before* the result


def test_structured_message_declassifies_trust_not_data():
    gw, _ = make()
    gw.spawn("s", "planner", "a", "data_analyst")
    gw.call_tool("s", "a", "sql_query", {"store": "customers_db"})
    gw.spawn("s", "planner", "r", "researcher")
    gw.call_tool("s", "r", "web_fetch", {})
    gw.send("s", "r", "a", structured=True)
    assert agent(gw, "a").trust is Trust.INTERNAL
    gw.send("s", "a", "planner", structured=True)
    assert agent(gw, "planner").labels == {"pii"}


def test_p1_requires_approval_and_approver_can_allow():
    gw, events = make()
    gw.spawn("s", "planner", "ops", "ops")
    gw.call_tool("s", "planner", "search", {})
    gw.send("s", "planner", "ops")
    resp = gw.call_tool("s", "ops", "restart_service", {"service": "x"})
    assert (resp.allowed, resp.rule) == (False, "P1")
    assert events[-1].decision == "approve_required"
    assert gw.call_tool("s", "ops", "read_logs", {}).allowed  # reads are fine

    gw2, events2 = make(approver=lambda *_: True)
    gw2.spawn("s", "planner", "ops", "ops")
    gw2.call_tool("s", "planner", "search", {})
    gw2.send("s", "planner", "ops")
    assert gw2.call_tool("s", "ops", "restart_service", {"service": "x"}).allowed
    gate = [e for e in events2 if e.kind is EventKind.GATE_DECISION][-1]
    assert gate.decision == "allow" and gate.rule == "P1" and gate.reason.startswith("approved")


def test_p2_blocks_pii_egress_and_quarantines():
    gw, events = make()
    gw.spawn("s", "planner", "a", "data_analyst")
    gw.spawn("s", "planner", "ops", "ops")
    gw.call_tool("s", "a", "sql_query", {"store": "customers_db"})
    gw.send("s", "a", "ops")
    resp = gw.call_tool("s", "ops", "send_email", {"to": "x"})
    assert (resp.allowed, resp.rule) == (False, "P2")
    assert agent(gw, "ops").tier is Tier.QUARANTINED
    assert events[-1].kind is EventKind.TIER_CHANGE


def test_p3_confused_deputy_only_for_untrusted_requests():
    gw, _ = make()
    gw.spawn("s", "planner", "r", "researcher")
    gw.spawn("s", "planner", "a", "data_analyst")
    gw.send("s", "r", "a")  # trusted request from a lower tier: normal delegation
    assert gw.call_tool("s", "a", "sql_query", {"store": "customers_db"}).allowed
    gw.call_tool("s", "r", "web_fetch", {})
    gw.send("s", "r", "a")  # now untrusted
    resp = gw.call_tool("s", "a", "sql_query", {"store": "customers_db"})
    assert (resp.allowed, resp.rule) == (False, "P3")
    assert agent(gw, "a").tier is Tier.CONSTRAINED
    # a request older than the window no longer counts
    gw2, _ = make()
    gw2.spawn("s", "planner", "r", "researcher")
    gw2.spawn("s", "planner", "a", "data_analyst")
    gw2.call_tool("s", "r", "web_fetch", {})
    gw2.send("s", "r", "a")
    gw2.clock.advance(11 * 60)
    assert gw2.call_tool("s", "a", "sql_query", {"store": "sales_db"}).allowed


def test_context_reset_clears_labels():
    gw, events = make()
    gw.call_tool("s", "planner", "search", {})
    gw.reset_context("s", "planner")
    assert agent(gw, "planner").trust is Trust.SYSTEM and not agent(gw, "planner").labels
    assert events[-1].kind is EventKind.CONTEXT_RESET


def test_rules_inactive_without_provenance():
    gw, _ = make(rules=None)
    gw.spawn("s", "planner", "ops", "ops")
    gw.call_tool("s", "planner", "search", {})
    gw.send("s", "planner", "ops")
    assert gw.call_tool("s", "ops", "restart_service", {}).allowed


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_every_attack_produces_ground_truth(name):
    s = generate(0, seed=11, attacks={name: ATTACKS[name]}, attacks_per_type=3,
                 policy=Policy(default_registry()))  # R1
    assert len(s.labels) == 3
    for lab in s.labels:
        assert lab.attack == name and lab.attackers and lab.harm
        assert lab.first_malicious_idx is not None
        # statically permitted unless the attack is about caps
        assert lab.prevented == (name == "A4")


def test_ablation_smoke():
    rungs = {r.key: r for r in RUNGS}
    res = [run_rung(rungs[k], [1], n_benign=40, n_attacks=3) for k in ("R1", "R2", "R2-reset-struct")]
    r1, r2, rs = res
    total = lambda r: sum(a.prevented for a in r.attacks.values())  # noqa: E731
    assert total(r2) > total(r1)
    assert r2.attacks["A1"].prevented == 3 and rs.attacks["A1"].prevented == 0
    assert r1.benign_blocks.total() == 0
    assert "Attack prevention" in render(res, [1], 40, 3)


def test_wilson_bounds():
    lo, hi = wilson(0, 10)
    assert lo == 0 and 0.2 < hi < 0.35
    lo, hi = wilson(10, 10)
    assert hi == 1 and 0.65 < lo < 0.8

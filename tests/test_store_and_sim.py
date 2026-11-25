from datetime import datetime, timezone

from slave.schema import Event, EventKind, Trust
from slave.sim.cli import main as sim_main
from slave.sim.swarm import generate
from slave.store import GENESIS, EventStore, chain_hash

T = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)


def ev(i: int) -> Event:
    return Event(event_id=f"e{i}", session_id="s", ts=T, kind=EventKind.TOOL_RESULT, src_id="a",
                 dst_id="web_fetch", trust=Trust.UNTRUSTED, data_classes={"b", "a"})


def test_canonical_json_is_order_stable():
    assert '"data_classes":["a","b"]' in ev(0).canonical_json()


def test_append_seals_chain_and_verifies(tmp_path):
    with EventStore(tmp_path / "e.duckdb", batch_size=3) as store:
        sealed = [store.append(ev(i)) for i in range(7)]
        assert sealed[0].prev_hash == GENESIS
        assert sealed[1].prev_hash == sealed[0].hash
        assert sealed[0].hash == chain_hash(GENESIS, ev(0).canonical_json())
        assert store.count() == 7
        v = store.verify()
        assert v.ok and v.checked == 7 and v.head_hash == sealed[-1].hash
        assert [e.event_id for e in store.session_events("s")] == [f"e{i}" for i in range(7)]


def test_chain_resumes_after_reopen(tmp_path):
    path = tmp_path / "e.duckdb"
    with EventStore(path) as store:
        store.append(ev(0))
        head = store.head_hash
    with EventStore(path) as store:
        assert store.head_hash == head
        assert store.append(ev(1)).prev_hash == head
        assert store.verify().ok


def test_tampering_is_detected(tmp_path):
    path = tmp_path / "e.duckdb"
    with EventStore(path) as store:
        for i in range(5):
            store.append(ev(i))
        store.flush()
        store.con.execute("UPDATE events SET body = replace(body, 'untrusted', 'internal') WHERE seq = 2")
        v = store.verify()
    assert not v.ok and v.bad_seq == 2 and "body" in v.reason


def test_deleted_row_is_detected(tmp_path):
    with EventStore(tmp_path / "e.duckdb") as store:
        for i in range(5):
            store.append(ev(i))
        store.flush()
        store.con.execute("DELETE FROM events WHERE seq = 3")
        v = store.verify()
    assert not v.ok and v.bad_seq == 3


def test_simulator_is_reproducible_and_benign():
    with EventStore() as a, EventStore() as b:
        sa = generate(60, seed=3, store=a)
        sb = generate(60, seed=3, store=b)
        assert sa.head_hash == sb.head_hash
        assert a.verify().ok
    assert sa.events == sb.events > 0
    # benign traffic must never trip the static policy
    assert sa.denials == {}
    assert set(sa.roles) == {"planner", "researcher", "coder", "reviewer", "data_analyst", "ops"}
    assert set(sa.workflows) == {"code_change", "research_report", "data_question", "ops_incident"}


def test_different_seed_differs():
    with EventStore() as a, EventStore() as b:
        assert generate(10, seed=1, store=a).head_hash != generate(10, seed=2, store=b).head_hash


def test_cli_generate_and_verify(tmp_path, capsys):
    out = tmp_path / "b.duckdb"
    assert sim_main(["generate", "--sessions", "20", "--seed", "5", "--out", str(out)]) == 0
    assert "hash chain verifies" in capsys.readouterr().out
    assert sim_main(["verify", str(out)]) == 0
    assert sim_main(["generate", "--sessions", "1", "--out", str(out)]) == 2  # refuses to clobber

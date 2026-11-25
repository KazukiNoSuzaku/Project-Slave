# Project Slave

Behavioral anomaly detection and surgical quarantine for multi-agent LLM swarms.

Every agent-to-agent message and agent-to-tool call passes through a gateway. The gateway labels data by where it came from, blocks risky calls before they run, scores agent behavior with calibrated unsupervised detectors, and quarantines only the agent that misbehaves. The rest of the swarm keeps working.

The full design is in [docs/design.md](docs/design.md).

## Status

| Component | State |
|---|---|
| Design v2 | done: [docs/design.md](docs/design.md) |
| Event schema | done: `slave/schema` |
| Ops Terminal dashboard | done: `slave/dashboard` (runs on a scripted demo feed) |
| **Phase 1:** gateway, static policy and caps, hash-chained event store, benign simulator | done: `slave/gateway`, `slave/store`, `slave/sim/swarm.py` |
| Phase 2: provenance rules P1–P3, attack library A1–A8 | next |
| Phases 3–5: detectors, calibration, enforcement | not started |

## Phase 1: gateway, event store, benign simulator

```bash
uv run slave-sim generate --sessions 10000 --seed 1   # → data/benign-seed1.duckdb
uv run slave-sim verify data/benign-seed1.duckdb      # recompute the hash chain
```

- **Gateway** (`slave/gateway`) is the single choke point. Agents spawn, message and call tools only through it. Every action becomes events, and tool calls are gated *before* they execute. Phase 1 has these rules:
  - T3: a quarantined agent is denied everything.
  - T2: a constrained agent is denied mutating and egress tools and spawning.
  - S1: a role may only call the tools on its allowlist.
  - S2: a call's sensitivity must not exceed the agent's privilege tier.
  - P4: caps on spawn depth, fan-out, spawn rate, call rate and identical-call repeats.
- **Event store** (`slave/store`) is append-only DuckDB. Each event is sealed with `sha256(prev_hash + "\n" + canonical_json)`. `verify()` recomputes the chain, so any edited, deleted or reordered row is detected.
- **Simulator** (`slave/sim/swarm.py`) has 6 roles and 4 workflows (code change, research report, data question, ops incident). Noise includes test-fix loops, review round-trips, sub-delegation and tool errors. It runs on simulated time and a seeded RNG, so the same seed always gives the same chain head.

Measured result for 10,000 sessions, seed 1, on an M-series laptop:

| Criterion | Result |
|---|---|
| ≥10k benign sessions | 10,000 sessions, 573,743 events, about 33 s |
| Gate overhead p99 ≤ 5 ms | p50 0.033 ms, p99 0.18 ms, max 27 ms |
| Hash chain verifies | OK, all 573,743 events |
| Reproducible | Two runs give the same head `236e3cb0…6f23` |
| Benign traffic never denied | 0 denials |

## Ops Terminal dashboard

```bash
uv sync
uv run slave-dashboard            # http://127.0.0.1:8000
uv run slave-dashboard --speed 3  # play the demo faster
```

Views (use the keys or click the tabs):

| Key | View | Shows |
|---|---|---|
| F1 / 1 | overview | KPIs with sparklines, the agent tree of the most severe session, and a live alert log |
| F2 / 2 | graph | Session list. For the selected session: agent tree (tiers, taint labels, allowed and denied tool calls) and message edges |
| F3 / 3 | taint | P1–P4 rule hits, and agents that carry taint labels or are flagged |
| F4 / 4 | replay | Incidents at tier 2 or above. Step through one session's event log with ← → |

By default, a **scripted demo feed** (`slave/sim/demo_feed.py`) drives the dashboard. It is not the real simulator. Each cycle replays four sessions: one benign session, an A1 prompt injection blocked by P1 and quarantined, an A4 spawn bomb stopped by the P4 cap, and an A5 ping-pong loop that gets elevated. It emits the control-plane decisions (gate, score, tier) that the real pipeline will produce later.

### API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/snapshot` | Current read model as JSON |
| GET | `/api/sessions/{id}/log` | Full event log of one session (used by replay) |
| POST | `/api/events` | Ingest one `Event` (`slave/schema/events.py`). This is where the gateway will plug in |
| WS | `/ws` | `hello` with a snapshot, then one `update` per event |

Run with `--no-demo` to show only events that are POSTed to `/api/events`.

## Development

```bash
uv run pytest
```

## License

MIT

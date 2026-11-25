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
| **Phase 2:** provenance labels, rules P1–P3, attack library A1–A8, ablation harness | done: `slave/gateway`, `slave/sim/attacks.py`, `slave/eval`, [results](docs/results/phase2-ablation.md) |
| Phase 3: fast-path features, Half-Space Trees, conformal calibration | next |
| Phases 4–5: graph autoencoder, enforcement | not started |

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
  - P1–P3 provenance rules, added in Phase 2 (see below).
- **Event store** (`slave/store`) is append-only DuckDB. Each event is sealed with `sha256(prev_hash + "\n" + canonical_json)`. `verify()` recomputes the chain, so any edited, deleted or reordered row is detected.
- **Simulator** (`slave/sim/swarm.py`) has 6 roles and 4 workflows (code change, research report, data question, ops incident). Noise includes test-fix loops, review round-trips, sub-delegation and tool errors. It runs on simulated time and a seeded RNG, so the same seed always gives the same chain head.

Measured result for 10,000 sessions, seed 1, on an M-series laptop, with all rules on:

| Criterion | Result |
|---|---|
| ≥10k benign sessions | 10,000 sessions, 576,155 events |
| Gate overhead p99 ≤ 5 ms | p50 0.010 ms, p99 0.026 ms |
| Hash chain verifies | OK, all 576,155 events |
| Reproducible | Two runs give the same head `61df43af…50f6` |
| Benign traffic under the Phase 1 rules alone | 0 denials (P1–P3 add a few; see Phase 2) |

## Phase 2: provenance and attacks

```bash
uv run slave-eval phase2 --seeds 5 --benign 2000 --attacks 40 --out docs/results/phase2-ablation.md
```

- **Provenance labels.** Every agent context carries a trust level and a set of data classes. Tool results, messages and spawns pass these labels along. A runtime context reset clears them. A *structured* (schema-validated) message passes data classes but not untrusted trust.
- **Rules:**
  - **P1:** an untrusted context making a high-sensitivity call that changes data or sends it out needs human approval.
  - **P2:** a context holding PII or restricted data cannot use an egress tool. The agent is quarantined.
  - **P3:** a confused-deputy request from an untrusted, lower-privilege agent is blocked, and the deputy is constrained.
- **Attacks A1–A8** (`slave/sim/attacks.py`) run inside normal sessions. Each records its ground truth: attacker agents, the first malicious event, and every harmful action with whether it executed.

Headline results (5 seeds, 10,000 benign sessions and 1,600 attack sessions per rung). The full table and caveats are in [docs/results/phase2-ablation.md](docs/results/phase2-ablation.md).

| Rung | Attacks prevented | Benign sessions with ≥1 block |
|---|---|---|
| R1: static policy and caps | 12% (A4 only) | 0% |
| R2: + provenance rules | 75% | 1.3% |
| R2 + context reset between tasks | 75% | 0% |
| R2 + reset + structured reports | 62% (A1 gets through again) | 0% |
| R2 with stricter P1 | 88% (catches A7) | 17% |

A5 (message loop) and A7 (mimicry through the normal delegation chain) pass the gate rules. They are the targets for the Phase 3 behavioural detectors.

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

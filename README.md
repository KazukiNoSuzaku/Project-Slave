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
| Gateway, provenance rules, simulator, detectors | not started (Phases 1–5 in the design) |

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

"""`slave-sim` — generate benign traces and verify event stores.

    slave-sim generate --sessions 10000 --seed 1 --out data/benign-seed1.duckdb
    slave-sim verify data/benign-seed1.duckdb
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from slave.sim.swarm import generate
from slave.store import EventStore

GATE_P99_BUDGET_MS = 5.0


def _fmt_counter(c) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(c.items())) or "none"


def cmd_generate(args: argparse.Namespace) -> int:
    out = Path(args.out or f"data/benign-seed{args.seed}.duckdb")
    if out.exists():
        if not args.overwrite:
            print(f"error: {out} exists (use --overwrite)", file=sys.stderr)
            return 2
        out.unlink()
    with EventStore(out) as store:
        s = generate(args.sessions, seed=args.seed, store=store)
        v = store.verify()

    p99_ok = s.gate_p99_ms is not None and s.gate_p99_ms <= GATE_P99_BUDGET_MS
    print(f"store           {out}")
    print(f"sessions        {s.sessions}  ({s.elapsed_s:.1f}s, {s.events / max(s.elapsed_s, 1e-9):,.0f} events/s)")
    print(f"events          {s.events:,}")
    print(f"workflows       {_fmt_counter(s.workflows)}")
    print(f"spawned roles   {_fmt_counter(s.roles)}")
    print(f"event kinds     {_fmt_counter(s.kinds)}")
    print(f"gate denials    {_fmt_counter(s.denials)}")
    print(f"gate latency    p50={s.gate_p50_ms:.4f}ms  p99={s.gate_p99_ms:.4f}ms  max={s.gate_max_ms:.3f}ms")
    print(f"chain head      {s.head_hash}")
    print()
    print("Phase 1 exit criteria")
    print(f"  [{'x' if s.sessions >= 10_000 else ' '}] ≥10k benign sessions generated ({s.sessions})")
    print(f"  [{'x' if p99_ok else ' '}] gate overhead p99 ≤ {GATE_P99_BUDGET_MS} ms ({s.gate_p99_ms:.4f} ms)")
    print(f"  [{'x' if v.ok else ' '}] hash chain verifies ({v.checked:,} events)")
    print("  [ ] reproducible: rerun with the same seed and compare the chain head")
    return 0 if (v.ok and p99_ok) else 1


def cmd_verify(args: argparse.Namespace) -> int:
    with EventStore(args.path) as store:
        v = store.verify()
    if v.ok:
        print(f"OK  {v.checked:,} events  head={v.head_hash}")
        return 0
    print(f"FAIL at seq {v.bad_seq}: {v.reason}  ({v.checked:,} events verified before it)")
    return 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="slave-sim", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="run the benign swarm simulator into an event store")
    g.add_argument("--sessions", type=int, default=10_000)
    g.add_argument("--seed", type=int, default=1)
    g.add_argument("--out", help="DuckDB path (default data/benign-seed<seed>.duckdb)")
    g.add_argument("--overwrite", action="store_true")
    g.set_defaults(fn=cmd_generate)
    v = sub.add_parser("verify", help="recompute and check an event store's hash chain")
    v.add_argument("path")
    v.set_defaults(fn=cmd_verify)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

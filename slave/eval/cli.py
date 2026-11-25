"""`slave-eval` — run evaluation ladders.

    slave-eval phase2 --seeds 5 --benign 2000 --attacks 40 --out docs/results/phase2-ablation.md
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from slave.eval.phase2 import RUNGS, render, run_rung


def cmd_phase2(args: argparse.Namespace) -> int:
    seeds = list(range(1, args.seeds + 1))
    rungs = [r for r in RUNGS if not args.rungs or r.key in args.rungs]
    results = []
    for rung in rungs:
        print(f"running {rung.key} …", file=sys.stderr, flush=True)
        results.append(run_rung(rung, seeds, args.benign, args.attacks))
    report = render(results, seeds, args.benign, args.attacks)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(report)
        print(f"wrote {args.out}", file=sys.stderr)
    print(report)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="slave-eval")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("phase2", help="gate-rule ablation (rungs R1–R2 variants)")
    g.add_argument("--seeds", type=int, default=5)
    g.add_argument("--benign", type=int, default=2000, help="benign sessions per seed")
    g.add_argument("--attacks", type=int, default=40, help="sessions per attack type per seed")
    g.add_argument("--rungs", nargs="*", help="subset of rung keys")
    g.add_argument("--out", help="write the markdown report here")
    g.set_defaults(fn=cmd_phase2)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

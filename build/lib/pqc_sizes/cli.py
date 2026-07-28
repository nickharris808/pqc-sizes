"""Command-line interface for pqc-sizes."""

from __future__ import annotations

import argparse
import json
import sys

from .core import (
    ALGORITHMS,
    TRANSPORTS,
    Credential,
    fragments_for,
    max_concurrent_contexts,
    reassembly_window,
)


def _fmt(n: int) -> str:
    return f"{n:,}"


def cmd_sizes(args: argparse.Namespace) -> int:
    rows = [a for a in ALGORITHMS.values() if not args.kind or a.kind == args.kind]
    if args.json:
        print(json.dumps([a.__dict__ for a in rows], indent=2))
        return 0
    print(f"{'algorithm':<26} {'kind':<14} {'cat':>4} {'pubkey':>9} {'ct/sig':>9}")
    print("-" * 66)
    for a in rows:
        cat = str(a.category) if a.category else "-"
        print(f"{a.name:<26} {a.kind:<14} {cat:>4} {_fmt(a.public_key):>9} "
              f"{_fmt(a.ciphertext_or_sig):>9}")
    return 0


def cmd_credential(args: argparse.Namespace) -> int:
    try:
        cred = Credential(ALGORITHMS[args.kem], ALGORITHMS[args.sig])
    except KeyError as exc:
        print(f"unknown algorithm: {exc}. Try `pqc-sizes sizes`.", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"total_bytes": cred.total_bytes,
                          "breakdown": cred.breakdown}, indent=2))
        return 0
    print(f"credential: {cred.kem.name} + {cred.sig.name}")
    for part, size in cred.breakdown.items():
        print(f"  {part:<34} {_fmt(size):>9} B")
    print(f"  {'TOTAL':<34} {_fmt(cred.total_bytes):>9} B")
    return 0


def cmd_fragments(args: argparse.Namespace) -> int:
    payload = TRANSPORTS.get(args.transport)
    if payload is None:
        try:
            payload = int(args.transport)
        except ValueError:
            print(f"unknown transport '{args.transport}'. Known: "
                  f"{', '.join(TRANSPORTS)} (or give a byte count).", file=sys.stderr)
            return 2
    if args.kem and args.sig:
        obj = Credential(ALGORITHMS[args.kem], ALGORITHMS[args.sig]).total_bytes
        what = f"{args.kem}+{args.sig} credential"
    else:
        obj = args.bytes
        what = f"{_fmt(obj)} B object"
    n = fragments_for(obj, payload)
    if args.json:
        print(json.dumps({"object_bytes": obj, "frame_payload": payload,
                          "fragments": n}, indent=2))
        return 0
    print(f"{what} over {args.transport} ({_fmt(payload)} B/frame): "
          f"{n} fragment{'s' if n != 1 else ''}")
    if n > 1:
        print(f"  -> fragmentation is mandatory; the receiver holds partial, "
              f"unauthenticated state across {n} frames")
    return 0


def cmd_window(args: argparse.Namespace) -> int:
    win = reassembly_window(args.largest_object, args.budget, args.concurrency)
    if args.json:
        print(json.dumps({
            "floor": win.floor, "ceiling": win.ceiling, "budget": win.budget,
            "concurrency": win.concurrency, "empty": win.is_empty,
            "recommended_cap": win.recommended,
            "max_safe_concurrency": max_concurrent_contexts(
                args.largest_object, args.budget),
        }, indent=2))
        return 1 if win.is_empty else 0
    print(win.explain())
    if not win.is_empty:
        print(f"  max safe concurrency at this object size: "
              f"{max_concurrent_contexts(args.largest_object, args.budget)}")
    return 1 if win.is_empty else 0


def cmd_sweep(args: argparse.Namespace) -> int:
    """Show where the window collapses as concurrency rises."""
    print(f"largest legitimate object: {_fmt(args.largest_object)} B   "
          f"budget: {_fmt(args.budget)} B")
    print(f"\n{'contexts':>9} {'ceiling':>12}   window")
    print("-" * 44)
    empty_at = None
    for c in range(1, args.max_concurrency + 1):
        win = reassembly_window(args.largest_object, args.budget, c)
        state = "EMPTY" if win.is_empty else "ok"
        if win.is_empty and empty_at is None:
            empty_at = c
        print(f"{c:>9} {_fmt(win.ceiling):>12}   {state}")
    if empty_at:
        print(f"\nwindow becomes EMPTY at {empty_at} concurrent contexts -- "
              f"that is this device's derived concurrency limit.")
    else:
        print(f"\nwindow non-empty through {args.max_concurrency} contexts.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pqc-sizes",
        description="Post-quantum object sizes, fragmentation, and the reassembly window.",
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sizes", help="list standardized algorithm sizes")
    s.add_argument("--kind", choices=["kem", "sig", "classical-kex", "classical-sig"])
    s.set_defaults(func=cmd_sizes)

    c = sub.add_parser("credential", help="total bytes for a KEM+signature credential")
    c.add_argument("--kem", default="ML-KEM-768")
    c.add_argument("--sig", default="ML-DSA-65")
    c.set_defaults(func=cmd_credential)

    f = sub.add_parser("fragments", help="fragment count on a transport")
    f.add_argument("transport", help=f"one of {', '.join(TRANSPORTS)} or a byte count")
    f.add_argument("--bytes", type=int, default=0)
    f.add_argument("--kem")
    f.add_argument("--sig")
    f.set_defaults(func=cmd_fragments)

    w = sub.add_parser("window", help="two-sided reassembly-capacity window")
    w.add_argument("--largest-object", type=int, required=True)
    w.add_argument("--budget", type=int, required=True)
    w.add_argument("--concurrency", type=int, required=True)
    w.set_defaults(func=cmd_window)

    q = sub.add_parser("sweep", help="find the concurrency at which the window empties")
    q.add_argument("--largest-object", type=int, required=True)
    q.add_argument("--budget", type=int, required=True)
    q.add_argument("--max-concurrency", type=int, default=8)
    q.set_defaults(func=cmd_sweep)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "cmd", None) == "fragments" and not (args.bytes or (args.kem and args.sig)):
        print("give --bytes N, or both --kem and --sig", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

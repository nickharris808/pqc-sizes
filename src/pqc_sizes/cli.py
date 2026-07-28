"""Command-line interface for pqc-sizes."""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

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


def _wrapped(text: str, indent: str = "", hang: str | None = None) -> str:
    """Wrap prose for a terminal.

    ``Window.explain()`` deliberately returns a single unbroken string: it is
    embedded verbatim in JSON by the MCP server, in GitHub Actions annotations
    by pqc-guard-action, and in Markdown by the Space, none of which want hard
    line breaks. Wrapping is therefore a property of *this* presentation layer
    only, applied at print time.
    """
    return textwrap.fill(
        text, width=78, initial_indent=indent,
        subsequent_indent=indent if hang is None else hang,
    )


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
        print(_wrapped(
            f"-> fragmentation is mandatory; the receiver holds partial, "
            f"unauthenticated state across {n} frames",
            indent="  ", hang="     "))
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
    print(_wrapped(win.explain()))
    if not win.is_empty:
        print(_wrapped(
            f"max safe concurrency at this object size: "
            f"{max_concurrent_contexts(args.largest_object, args.budget)}",
            indent="  "))
    return 1 if win.is_empty else 0


def cmd_budget(args: argparse.Namespace) -> int:
    """Invert the window: how much memory do I need for N contexts?

    `window` answers "is my budget enough?". Nobody starts there -- they start
    with a credential and a concurrency target and need the budget. Solving it
    by hand means re-deriving ceiling >= floor, which is exactly the arithmetic
    people get wrong.
    """
    # Refuse degenerate inputs rather than computing with them. `7533 * 0` is 0,
    # and printing "minimum budget 0 B" would be a confident answer to a question
    # nobody meant to ask.
    if args.concurrency < 1:
        print(f"--concurrency must be at least 1, got {args.concurrency}\n"
              f"  fix: concurrency is the worst-case number of reassembly contexts "
              f"held at once; zero contexts is not a deployment", file=sys.stderr)
        return 2
    if args.largest_object and args.largest_object < 1:
        print(f"--largest-object must be positive, got {args.largest_object}\n"
              f"  fix: give the size in bytes of the biggest object you must accept",
              file=sys.stderr)
        return 2

    if args.kem and args.sig:
        try:
            largest = Credential(ALGORITHMS[args.kem], ALGORITHMS[args.sig]).total_bytes
        except KeyError as exc:
            print(f"unknown algorithm: {exc}. Try `pqc-sizes sizes`.", file=sys.stderr)
            return 2
        what = f"{args.kem} + {args.sig}"
    else:
        largest = args.largest_object
        what = f"{_fmt(largest)} B object"

    # ceiling = budget // concurrency must be >= floor, so budget >= floor * concurrency.
    required = largest * args.concurrency

    if args.json:
        print(json.dumps({
            "largest_object": largest, "concurrency": args.concurrency,
            "required_budget": required,
            "headroom_at": {str(m): largest * args.concurrency * m for m in (2, 4)},
        }, indent=2))
        return 0

    print(f"{what}: {_fmt(largest)} B, {args.concurrency} concurrent contexts")
    print(f"  minimum budget   {_fmt(required)} B")
    print(_wrapped(
        f"at exactly this budget the window is a single point ({_fmt(largest)} B): "
        f"the only admissible cap is the object size itself, leaving no headroom "
        f"for a larger legitimate object.", indent="  "))
    print()
    print(f"  2x headroom      {_fmt(required * 2)} B")
    print(f"  4x headroom      {_fmt(required * 4)} B")
    return 0


#: Keys a config file may set. Anything else is a typo, and a typo that is
#: silently ignored is a config that does not do what its author thinks.
_CONFIG_KEYS = {"kem", "sig", "largest_object", "budget", "concurrency", "transport"}


def cmd_check(args: argparse.Namespace) -> int:
    """Gate on a committed config file instead of four hand-typed flags.

    Reads JSON (or YAML, if PyYAML happens to be installed) so a team can keep
    its reassembly parameters under review alongside the code they describe.
    """
    path = Path(args.config)
    if not path.exists():
        print(f"config not found: {path}\n"
              f"  fix: create it, e.g.\n"
              f"       {{\"kem\": \"ML-KEM-768\", \"sig\": \"ML-DSA-65\",\n"
              f"        \"budget\": 65536, \"concurrency\": 4}}", file=sys.stderr)
        return 2

    text = path.read_text(encoding="utf-8")
    try:
        cfg = json.loads(text)
    except json.JSONDecodeError as exc:
        try:
            import yaml
        except ImportError:
            print(f"{path} is not valid JSON: {exc}\n"
                  f"  fix: correct the JSON, or `pip install pyyaml` to use YAML.",
                  file=sys.stderr)
            return 2
        try:
            cfg = yaml.safe_load(text)
        except Exception as yexc:  # noqa: BLE001 - report whatever the parser says
            print(f"{path} parses as neither JSON nor YAML: {yexc}", file=sys.stderr)
            return 2

    if not isinstance(cfg, dict):
        print(f"{path} must contain a mapping of settings, got "
              f"{type(cfg).__name__}", file=sys.stderr)
        return 2

    unknown = sorted(set(cfg) - _CONFIG_KEYS)
    if unknown:
        print(f"unknown setting(s) in {path}: {', '.join(unknown)}\n"
              f"  fix: valid keys are {', '.join(sorted(_CONFIG_KEYS))}", file=sys.stderr)
        return 2

    # The largest legitimate object is either given outright or derived from the
    # credential, so a config need only name its suite.
    largest = cfg.get("largest_object")
    if largest is None:
        kem, sig = cfg.get("kem"), cfg.get("sig")
        if not (kem and sig):
            print(f"{path} must set either largest_object, or both kem and sig\n"
                  f"  fix: add \"kem\" and \"sig\", or an explicit \"largest_object\"",
                  file=sys.stderr)
            return 2
        try:
            largest = Credential(ALGORITHMS[kem], ALGORITHMS[sig]).total_bytes
        except KeyError as exc:
            print(f"unknown algorithm {exc} in {path}\n"
                  f"  fix: see `pqc-sizes sizes` for the known names", file=sys.stderr)
            return 2

    for required in ("budget", "concurrency"):
        if cfg.get(required) is None:
            print(f"{path} is missing \"{required}\"\n"
                  f"  fix: budget is total reassembly bytes; concurrency is the "
                  f"worst-case number of simultaneous contexts", file=sys.stderr)
            return 2

    win = reassembly_window(largest, cfg["budget"], cfg["concurrency"])
    safe = max_concurrent_contexts(largest, cfg["budget"])

    if getattr(args, "format", None) == "sarif":
        from .report import write_sarif
        text = write_sarif(win, safe, str(path), args.output)
        print(f"wrote sarif report to {args.output}" if args.output else text)
        return 1 if win.is_empty else 0

    if args.json:
        print(json.dumps({
            "config": str(path), "floor": win.floor, "ceiling": win.ceiling,
            "budget": win.budget, "concurrency": win.concurrency,
            "empty": win.is_empty, "recommended_cap": win.recommended,
            "max_safe_concurrency": safe,
        }, indent=2))
        return 1 if win.is_empty else 0

    print(f"{path}: {_fmt(largest)} B object, {_fmt(cfg['budget'])} B budget, "
          f"{cfg['concurrency']} contexts")
    print(_wrapped(win.explain(), indent="  "))
    if not win.is_empty:
        print(_wrapped(f"max safe concurrency at this object size: {safe}",
                       indent="  "))
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
        print("\n" + _wrapped(
            f"window becomes EMPTY at {empty_at} concurrent contexts -- "
            f"that is this device's derived concurrency limit."))
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

    bg = sub.add_parser("budget", help="how much memory do N contexts need?")
    bg.add_argument("--largest-object", type=int, default=0)
    bg.add_argument("--kem")
    bg.add_argument("--sig")
    bg.add_argument("--concurrency", type=int, required=True)
    bg.set_defaults(func=cmd_budget)

    ck = sub.add_parser("check", help="gate on a committed config file")
    ck.add_argument("config", help="JSON (or YAML) file of reassembly settings")
    ck.add_argument("--format", choices=["text", "sarif"], default="text",
                    help="sarif emits a GitHub code-scanning report")
    ck.add_argument("-o", "--output", help="write the report to a file")
    ck.set_defaults(func=cmd_check)

    q = sub.add_parser("sweep", help="find the concurrency at which the window empties")
    q.add_argument("--largest-object", type=int, required=True)
    q.add_argument("--budget", type=int, required=True)
    q.add_argument("--max-concurrency", type=int, default=8)
    q.set_defaults(func=cmd_sweep)
    return p


#: Maps a validation failure to the flag the user actually needs to change. A
#: traceback tells them the assertion that fired; this tells them what to type.
_REMEDY = {
    "concurrency": "--concurrency must be at least 1 (the number of reassembly "
                   "contexts held at once)",
    "memory_budget": "--budget must be a positive byte count (the total reassembly "
                     "memory available)",
    "largest_legitimate_object": "--largest-object must be a positive byte count "
                                 "(the biggest object you must accept)",
    "frame_payload": "the transport payload must be positive; pass a known transport "
                     f"({', '.join(list(TRANSPORTS)[:3])}, ...) or --bytes N",
    "object_bytes": "the object size must be positive",
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "cmd", None) == "fragments" and not (args.bytes or (args.kem and args.sig)):
        print("give --bytes N, or both --kem and --sig", file=sys.stderr)
        return 2
    if getattr(args, "cmd", None) == "budget" and not (
            args.largest_object or (args.kem and args.sig)):
        print("give --largest-object N, or both --kem and --sig", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except ValueError as exc:
        # Domain validation reaches the user as a usage error naming the fix, not as
        # a stack trace. Exit 2 (usage) rather than 1, which this CLI reserves for
        # "the check ran and the answer is bad" -- a CI gate must be able to tell a
        # broken invocation apart from a genuine empty window.
        message = str(exc)
        for key, remedy in _REMEDY.items():
            if key in message:
                print(f"{message}\n  fix: {remedy}", file=sys.stderr)
                return 2
        print(f"{message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

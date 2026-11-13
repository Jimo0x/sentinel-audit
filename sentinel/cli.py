"""Command-line interface for Sentinel Audit."""
from __future__ import annotations

import argparse
import sys

from sentinel import __version__
from sentinel.core.engine import Engine
from sentinel.core.report import to_json, to_markdown, write_reports
from sentinel.core.scope import Scope, ScopeError
from sentinel.modules import all_modules
from sentinel.modules.base import ModuleContext

DEFAULT_MODULES = ["discovery", "portscan", "services", "tls", "http", "dns"]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel Audit — authorized security auditing framework.",
        epilog="Authorized testing only. A scope file is required for every run.",
    )
    p.add_argument("--version", action="version", version=f"sentinel {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # run ---------------------------------------------------------------
    run = sub.add_parser("run", help="run an audit against authorized targets")
    run.add_argument("--scope", required=True, help="path to engagement scope file (YAML/JSON)")
    run.add_argument("--target", action="append", default=[],
                     help="limit to this target (repeatable). Must be in scope. "
                          "Defaults to every target in the scope file.")
    run.add_argument("--modules", default=None,
                     help=f"comma-separated modules (default: scope default or {','.join(DEFAULT_MODULES)})")
    run.add_argument("--ports", default=None, help="port spec: common|full|RANGE|LIST")
    run.add_argument("--timeout", type=float, default=None, help="per-connection timeout seconds")
    run.add_argument("--concurrency", type=int, default=None, help="max concurrent connections")
    run.add_argument("--out", default=None, help="directory to write JSON/MD/HTML reports")
    run.add_argument("--format", default="md",
                     help="stdout format: md|json|none (default md). Files written if --out given.")
    run.add_argument("--yes", action="store_true",
                     help="skip the interactive authorization confirmation")

    # modules -----------------------------------------------------------
    sub.add_parser("modules", help="list available audit modules")

    # scope -------------------------------------------------------------
    sc = sub.add_parser("scope", help="validate a scope file and show what it authorizes")
    sc.add_argument("--scope", required=True, help="path to engagement scope file")

    # gui ---------------------------------------------------------------
    gui = sub.add_parser("gui", help="launch the local desktop web UI")
    gui.add_argument("--host", default="127.0.0.1")
    gui.add_argument("--port", type=int, default=8787)
    gui.add_argument("--no-browser", action="store_true", help="don't auto-open a browser")

    return p


def _resolve_run_config(scope: Scope, args) -> tuple[list[str], list[str], ModuleContext]:
    defaults = scope.defaults or {}
    specs = args.target or list(scope.targets)

    modules_arg = args.modules or defaults.get("modules") or DEFAULT_MODULES
    if isinstance(modules_arg, str):
        module_names = [m.strip() for m in modules_arg.split(",") if m.strip()]
    else:
        module_names = list(modules_arg)

    ctx = ModuleContext(
        scope=scope,
        timeout=args.timeout if args.timeout is not None else float(defaults.get("timeout", 2.0)),
        concurrency=args.concurrency if args.concurrency is not None else int(defaults.get("concurrency", 100)),
        ports=args.ports or str(defaults.get("ports", "common")),
    )
    return specs, module_names, ctx


def cmd_run(args) -> int:
    try:
        scope = Scope.load(args.scope)
    except ScopeError as exc:
        print(f"[scope error] {exc}", file=sys.stderr)
        return 2

    print(scope.banner())

    specs, module_names, ctx = _resolve_run_config(scope, args)

    # Validate module names early.
    available = set(all_modules())
    unknown = [m for m in module_names if m not in available]
    if unknown:
        print(f"[error] unknown module(s): {', '.join(unknown)}. "
              f"Available: {', '.join(sorted(available))}", file=sys.stderr)
        return 2

    print(f"\nModules : {', '.join(module_names)}")
    print(f"Targets : {', '.join(specs) or '(none)'}")
    print(f"Ports   : {ctx.ports}  Timeout: {ctx.timeout}s  Concurrency: {ctx.concurrency}\n")

    if not args.yes and sys.stdin.isatty():
        resp = input("Proceed with audit of the above IN-SCOPE targets? [y/N] ").strip().lower()
        if resp not in ("y", "yes"):
            print("Aborted.")
            return 1

    engine = Engine(scope, ctx, progress=lambda m: print(m))
    report = engine.run(specs, module_names)

    # stdout
    fmt = (args.format or "md").lower()
    print("\n" + "-" * 70)
    if fmt == "json":
        print(to_json(report))
    elif fmt == "md":
        print(to_markdown(report))
    elif fmt != "none":
        print(f"[warn] unknown --format {fmt!r}; use md|json|none")

    # files
    if args.out:
        paths = write_reports(report, args.out)
        print("\nReports written:")
        for p in paths:
            print(f"  - {p}")

    counts = report.severity_counts()
    high = counts["CRITICAL"] + counts["HIGH"]
    print(f"\nDone. Findings — "
          f"Critical:{counts['CRITICAL']} High:{counts['HIGH']} "
          f"Medium:{counts['MEDIUM']} Low:{counts['LOW']} Info:{counts['INFO']}")
    # Non-zero exit if notable findings, useful in CI gates.
    return 0 if high == 0 else 3


def cmd_modules(_args) -> int:
    print("Available audit modules:\n")
    for name, mod in sorted(all_modules().items()):
        print(f"  {name:<10} {mod.description}")
    return 0


def cmd_scope(args) -> int:
    try:
        scope = Scope.load(args.scope)
    except ScopeError as exc:
        print(f"[scope error] {exc}", file=sys.stderr)
        return 2
    print(scope.banner())
    print("\nResolving authorization for each target:\n")
    for spec in scope.targets:
        res = scope.authorize(spec)
        mark = "AUTHORIZED" if res.authorized else "DENIED    "
        ipinfo = f" -> {res.ip}" if res.ip else ""
        print(f"  [{mark}] {spec}{ipinfo}  ({res.reason})")
    return 0


def cmd_gui(args) -> int:
    from sentinel.gui.app import serve
    return serve(host=args.host, port=args.port, open_browser=not args.no_browser)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    dispatch = {
        "run": cmd_run,
        "modules": cmd_modules,
        "scope": cmd_scope,
        "gui": cmd_gui,
    }
    try:
        return dispatch[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

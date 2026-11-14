"""Command-line interface for Sentinel Audit."""
from __future__ import annotations

import argparse
import sys

from sentinel import __version__
from sentinel.core.engine import Engine
from sentinel.core.models import Severity
from sentinel.core.report import to_json, to_markdown, write_reports
from sentinel.core.scope import Scope, ScopeError
from sentinel.modules import all_modules
from sentinel.modules.base import ModuleContext

DEFAULT_MODULES = ["discovery", "portscan", "services", "tls", "http", "dns"]

# Named bundles of modules for common audit goals.
PROFILES = {
    "quick": ["discovery", "portscan", "services"],
    "default": DEFAULT_MODULES,
    "web": ["http", "tls", "exposure", "webcrawl", "vulnhints"],
    "server": ["discovery", "portscan", "services", "tls", "sshaudit", "vulnhints"],
    "email": ["dns", "emailsec"],
    "full": ["discovery", "portscan", "services", "tls", "http", "dns",
             "webcrawl", "exposure", "emailsec", "sshaudit", "vulnhints"],
}


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
    run.add_argument("--profile", default=None, choices=sorted(PROFILES),
                     help="module bundle: " + " | ".join(f"{k}={','.join(v)}" for k, v in PROFILES.items()))
    run.add_argument("--modules", default=None,
                     help=f"comma-separated modules (overrides --profile; default: scope default or {','.join(DEFAULT_MODULES)})")
    run.add_argument("--ports", default=None, help="port spec: common|full|RANGE|LIST")
    run.add_argument("--timeout", type=float, default=None, help="per-connection timeout seconds")
    run.add_argument("--concurrency", type=int, default=None, help="max concurrent connections (port scan)")
    run.add_argument("--target-concurrency", type=int, default=4,
                     help="how many targets to audit in parallel (default 4)")
    run.add_argument("--rate-delay", type=float, default=0.0,
                     help="minimum seconds between requests (politeness; default 0)")
    run.add_argument("--out", default=None, help="directory to write report files")
    run.add_argument("--out-formats", default="json,md,html",
                     help="comma list of file formats for --out: json,md,html,sarif,csv")
    run.add_argument("--format", default="md",
                     help="stdout format: md|json|none (default md). Files written if --out given.")
    run.add_argument("--fail-on", default="high",
                     choices=["critical", "high", "medium", "low", "info", "none"],
                     help="exit non-zero if any finding at/above this severity (default high)")
    run.add_argument("--yes", action="store_true",
                     help="skip the interactive authorization confirmation")

    # modules -----------------------------------------------------------
    sub.add_parser("modules", help="list available audit modules")

    # scope -------------------------------------------------------------
    sc = sub.add_parser("scope", help="validate a scope file and show what it authorizes")
    sc.add_argument("--scope", required=True, help="path to engagement scope file")

    # diff --------------------------------------------------------------
    df = sub.add_parser("diff", help="compare two JSON reports (remediation tracking)")
    df.add_argument("old", help="path to the older report .json")
    df.add_argument("new", help="path to the newer report .json")
    df.add_argument("--json", action="store_true", help="output machine-readable JSON")

    # import-nmap -------------------------------------------------------
    nm = sub.add_parser("import-nmap", help="convert an nmap XML scan into a Sentinel report")
    nm.add_argument("xml", help="path to nmap -oX output")
    nm.add_argument("--scope", default=None, help="optional scope file to tag in/out-of-scope hosts")
    nm.add_argument("--out", default=None, help="directory to write report files")
    nm.add_argument("--out-formats", default="json,md,html", help="comma list: json,md,html,sarif,csv")

    # gui ---------------------------------------------------------------
    gui = sub.add_parser("gui", help="launch the local desktop web UI")
    gui.add_argument("--host", default="127.0.0.1")
    gui.add_argument("--port", type=int, default=8787)
    gui.add_argument("--no-browser", action="store_true", help="don't auto-open a browser")
    gui.add_argument("--native", action="store_true",
                     help="open in a native OS window (requires pywebview; falls back to browser)")

    return p


def _resolve_run_config(scope: Scope, args) -> tuple[list[str], list[str], ModuleContext]:
    defaults = scope.defaults or {}
    specs = args.target or list(scope.targets)

    if args.modules:
        modules_arg = args.modules
    elif getattr(args, "profile", None):
        modules_arg = PROFILES[args.profile]
    else:
        modules_arg = defaults.get("modules") or DEFAULT_MODULES
    if isinstance(modules_arg, str):
        module_names = [m.strip() for m in modules_arg.split(",") if m.strip()]
    else:
        module_names = list(modules_arg)

    ctx = ModuleContext(
        scope=scope,
        timeout=args.timeout if args.timeout is not None else float(defaults.get("timeout", 2.0)),
        concurrency=args.concurrency if args.concurrency is not None else int(defaults.get("concurrency", 100)),
        ports=args.ports or str(defaults.get("ports", "common")),
        rate_delay=args.rate_delay if getattr(args, "rate_delay", 0.0) else float(defaults.get("rate_delay", 0.0)),
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

    engine = Engine(scope, ctx, progress=lambda m: print(m),
                    target_concurrency=args.target_concurrency)
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
        fmts = tuple(f.strip() for f in args.out_formats.split(",") if f.strip())
        paths = write_reports(report, args.out, formats=fmts)
        print("\nReports written:")
        for p in paths:
            print(f"  - {p}")

    counts = report.severity_counts()
    print(f"\nDone. Findings — "
          f"Critical:{counts['CRITICAL']} High:{counts['HIGH']} "
          f"Medium:{counts['MEDIUM']} Low:{counts['LOW']} Info:{counts['INFO']}")

    # CI gate: non-zero exit if anything at/above the --fail-on threshold.
    if args.fail_on == "none":
        return 0
    threshold = Severity.from_str(args.fail_on)
    triggered = sum(c for s, c in counts.items() if Severity[s] >= threshold)
    if triggered:
        print(f"Gate: {triggered} finding(s) at or above {threshold.label} → exit 3")
        return 3
    return 0


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


def cmd_diff(args) -> int:
    from sentinel.core.diff import diff_reports, render_diff_text
    try:
        d = diff_reports(args.old, args.new)
    except (OSError, ValueError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(d.to_dict(), indent=2))
    else:
        print(render_diff_text(d))
    return 0


def cmd_import_nmap(args) -> int:
    from sentinel.integrations.nmap_import import import_nmap
    try:
        scope = Scope.load(args.scope) if args.scope else None
    except ScopeError as exc:
        print(f"[scope error] {exc}", file=sys.stderr)
        return 2
    try:
        report = import_nmap(args.xml, scope=scope)
    except (OSError, ValueError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    print(to_markdown(report))
    if args.out:
        fmts = tuple(f.strip() for f in args.out_formats.split(",") if f.strip())
        for p in write_reports(report, args.out, formats=fmts):
            print(f"  - {p}")
    return 0


def cmd_gui(args) -> int:
    if getattr(args, "native", False):
        from sentinel.desktop import launch
        return launch(host=args.host, port=args.port)
    from sentinel.gui.app import serve
    return serve(host=args.host, port=args.port, open_browser=not args.no_browser)


def main(argv: list[str] | None = None) -> int:
    # Load any user/third-party plugins so their modules register before dispatch.
    try:
        from sentinel.modules.plugins import load_plugins
        load_plugins()
    except Exception:
        pass
    parser = _build_parser()
    args = parser.parse_args(argv)
    dispatch = {
        "run": cmd_run,
        "modules": cmd_modules,
        "scope": cmd_scope,
        "diff": cmd_diff,
        "import-nmap": cmd_import_nmap,
        "gui": cmd_gui,
    }
    try:
        return dispatch[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

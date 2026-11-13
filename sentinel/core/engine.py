"""Orchestration engine: runs selected modules over in-scope targets.

Targets are audited concurrently (bounded by `target_concurrency`). Within a
single target the modules run sequentially, which lets `portscan` populate the
shared port cache before the service/TLS/HTTP/exposure modules need it — so the
network is probed once per port, not once per module. Per-target progress is
buffered and flushed atomically so parallel output stays readable.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

from sentinel.core.models import AuditReport, ModuleResult, Target
from sentinel.core.scope import Scope
from sentinel.modules.base import AuditModule, ModuleContext, get_module


ProgressHook = Callable[[str], None]


class Engine:
    def __init__(self, scope: Scope, ctx: ModuleContext, progress: ProgressHook | None = None,
                 target_concurrency: int = 4):
        self.scope = scope
        self.ctx = ctx
        self._progress = progress or (lambda msg: None)
        self._plock = threading.Lock()
        self.target_concurrency = max(1, target_concurrency)

    def progress(self, msg: str) -> None:
        with self._plock:
            self._progress(msg)

    # ------------------------------------------------------------------------
    def resolve_targets(self, specs: Iterable[str]) -> tuple[list[Target], list[str]]:
        allowed, denied = self.scope.filter_authorized(specs)
        targets = [Target(spec=a.spec, ip=a.ip) for a in allowed]
        denied_msgs = [f"{d.spec}: {d.reason}" for d in denied]
        return targets, denied_msgs

    # ------------------------------------------------------------------------
    def run(self, specs: Iterable[str], module_names: list[str]) -> AuditReport:
        modules = [get_module(n) for n in module_names]
        targets, denied = self.resolve_targets(specs)

        for msg in denied:
            self.progress(f"[SKIP] out of scope — {msg}")

        report = AuditReport(
            engagement=self.scope.engagement,
            authorized_by=self.scope.authorized_by,
            targets=targets,
            scope_summary=self.scope.summary(),
        )
        report.scope_summary["denied_targets"] = denied

        if not targets:
            self.progress("[!] No authorized targets to scan.")
            report.finished = time.time()
            return report

        workers = min(self.target_concurrency, len(targets))
        if workers == 1:
            for target in targets:
                report.results.extend(self._audit_target(target, modules))
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(self._audit_target, t, modules): t for t in targets}
                for fut in as_completed(futures):
                    report.results.extend(fut.result())

        report.scope_summary["port_probe_stats"] = self.ctx.port_cache.stats()
        report.finished = time.time()
        return report

    # ------------------------------------------------------------------------
    def _audit_target(self, target: Target, modules: list[AuditModule]) -> list[ModuleResult]:
        """Run all modules against one target, buffering progress for atomic output."""
        buffer: list[str] = [f"[*] Auditing {target.display()}"]
        results: list[ModuleResult] = []
        for module in modules:
            result = self._run_module(module, target)
            results.append(result)
            if result.error:
                buffer.append(f"    - {module.name}: error ({result.error})")
            else:
                buffer.append(f"    - {module.name}: {len(result.findings)} finding(s)")
        self.progress("\n".join(buffer))
        return results

    def _run_module(self, module: AuditModule, target: Target) -> ModuleResult:
        result = ModuleResult(module=module.name, target=target.display())
        try:
            result.findings = module.run(target, self.ctx)
        except Exception as exc:  # modules must never crash the whole run
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.finished = time.time()
        return result

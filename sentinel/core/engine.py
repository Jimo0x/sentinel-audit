"""Orchestration engine: runs selected modules over in-scope targets."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

from sentinel.core.models import AuditReport, ModuleResult, Target
from sentinel.core.scope import Scope
from sentinel.modules.base import AuditModule, ModuleContext, get_module


ProgressHook = Callable[[str], None]


class Engine:
    def __init__(self, scope: Scope, ctx: ModuleContext, progress: ProgressHook | None = None):
        self.scope = scope
        self.ctx = ctx
        self.progress = progress or (lambda msg: None)

    # ------------------------------------------------------------------------
    def resolve_targets(self, specs: Iterable[str]) -> tuple[list[Target], list[str]]:
        """Authorize + resolve specs. Returns (authorized_targets, denied_messages)."""
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

        for target in targets:
            self.progress(f"[*] Auditing {target.display()}")
            for module in modules:
                result = self._run_module(module, target)
                report.results.append(result)
                n = len(result.findings)
                if result.error:
                    self.progress(f"    - {module.name}: error ({result.error})")
                else:
                    self.progress(f"    - {module.name}: {n} finding(s)")

        report.finished = time.time()
        return report

    # ------------------------------------------------------------------------
    def _run_module(self, module: AuditModule, target: Target) -> ModuleResult:
        result = ModuleResult(module=module.name, target=target.display())
        try:
            result.findings = module.run(target, self.ctx)
        except Exception as exc:  # modules must never crash the whole run
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.finished = time.time()
        return result

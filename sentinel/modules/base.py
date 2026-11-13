"""Audit module interface and registry.

A module is a small, focused check. It receives a resolved `Target` and a
`ModuleContext` (timeouts, port selection, scope) and returns `Finding`s.

Register a module with the `@register` decorator; it then becomes available
by name to the CLI and engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Type

from sentinel.core.models import Finding, Target
from sentinel.core.scope import Scope


@dataclass
class ModuleContext:
    """Run-time knobs passed to every module."""

    scope: Scope
    timeout: float = 2.0
    concurrency: int = 100
    ports: str = "common"            # "common" | "full" | "22,80,443" | "1-1024"
    extra: dict = field(default_factory=dict)


class AuditModule:
    """Base class for all audit modules."""

    #: short, stable identifier used on the CLI (e.g. "portscan")
    name: str = "base"
    #: one-line human description
    description: str = ""

    def run(self, target: Target, ctx: ModuleContext) -> list[Finding]:
        """Perform the check against `target`. Must be overridden."""
        raise NotImplementedError

    # convenience ------------------------------------------------------------
    def finding(self, target: Target, title: str, **kw) -> Finding:
        return Finding(module=self.name, target=target.display(), title=title, **kw)


# --- registry ---------------------------------------------------------------
_REGISTRY: dict[str, AuditModule] = {}


def register(cls: Type[AuditModule]) -> Type[AuditModule]:
    instance = cls()
    if not instance.name or instance.name == "base":
        raise ValueError(f"module {cls.__name__} must define a unique `name`")
    if instance.name in _REGISTRY:
        raise ValueError(f"duplicate module name: {instance.name}")
    _REGISTRY[instance.name] = instance
    return cls


def get_module(name: str) -> AuditModule:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown module: {name!r}. Available: {', '.join(sorted(_REGISTRY))}")


def all_modules() -> dict[str, AuditModule]:
    return dict(_REGISTRY)

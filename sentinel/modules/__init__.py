"""Audit modules. Importing this package registers all built-in modules."""
from __future__ import annotations

from sentinel.modules.base import AuditModule, ModuleContext, get_module, all_modules

# Importing each module triggers its @register decorator.
from sentinel.modules import (  # noqa: F401  (side-effect registration)
    discovery,
    portscan,
    services,
    tls_audit,
    http_audit,
    dns_enum,
)

__all__ = ["AuditModule", "ModuleContext", "get_module", "all_modules"]

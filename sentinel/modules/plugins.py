"""Plugin loader for custom/third-party audit modules.

Sentinel is extensible: drop your own module (a subclass of AuditModule that
calls @register) anywhere importable and point Sentinel at it. Three mechanisms,
tried in order:

1. The ``SENTINEL_PLUGINS`` environment variable — a comma-separated list of
   importable module paths (e.g. ``mycorp.sentinel_mods,extra_checks``).
2. Python files in a ``~/.sentinel/plugins/`` directory.
3. Installed packages exposing a ``sentinel.modules`` entry point.

Importing a plugin module runs its ``@register`` decorators, so its modules
become available to the CLI/engine exactly like the built-ins.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from pathlib import Path


def load_plugins(verbose: bool = False) -> list[str]:
    """Load all discoverable plugins. Returns the names of modules imported."""
    loaded: list[str] = []
    loaded += _load_from_env(verbose)
    loaded += _load_from_dir(verbose)
    loaded += _load_from_entry_points(verbose)
    return loaded


def _safe_import(name: str, verbose: bool) -> bool:
    try:
        importlib.import_module(name)
        return True
    except Exception as exc:  # a bad plugin must never break the tool
        if verbose:
            print(f"[plugin] failed to import {name}: {exc}", file=sys.stderr)
        return False


def _load_from_env(verbose: bool) -> list[str]:
    out = []
    spec = os.environ.get("SENTINEL_PLUGINS", "")
    for name in (n.strip() for n in spec.split(",") if n.strip()):
        if _safe_import(name, verbose):
            out.append(name)
    return out


def _load_from_dir(verbose: bool) -> list[str]:
    out = []
    plugin_dir = Path(os.environ.get("SENTINEL_PLUGIN_DIR", str(Path.home() / ".sentinel" / "plugins")))
    if not plugin_dir.is_dir():
        return out
    for py in sorted(plugin_dir.glob("*.py")):
        if py.name.startswith("_"):
            continue
        modname = f"sentinel_plugin_{py.stem}"
        try:
            spec = importlib.util.spec_from_file_location(modname, py)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[modname] = mod
            spec.loader.exec_module(mod)
            out.append(modname)
        except Exception as exc:
            if verbose:
                print(f"[plugin] failed to load {py}: {exc}", file=sys.stderr)
    return out


def _load_from_entry_points(verbose: bool) -> list[str]:
    out = []
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return out
    try:
        eps = entry_points()
        group = eps.select(group="sentinel.modules") if hasattr(eps, "select") else eps.get("sentinel.modules", [])
    except Exception:
        return out
    for ep in group:
        try:
            ep.load()
            out.append(ep.value)
        except Exception as exc:
            if verbose:
                print(f"[plugin] failed to load entry point {ep.name}: {exc}", file=sys.stderr)
    return out

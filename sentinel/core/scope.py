"""Rules-of-engagement scope parsing and authorization enforcement.

This module is the safety rail that makes Sentinel an *authorized* auditing
tool. No module is allowed to touch a target the scope has not authorized.

A scope file (YAML or JSON) looks like::

    engagement: "ACME internal review"
    authorized_by: "jane.doe@acme.example — ticket SEC-4821"
    authorized_until: "2026-12-31"
    targets:
      - 127.0.0.1
      - 192.168.56.0/24
      - test.internal.acme.example
    exclude:
      - 192.168.56.1

Authorization rules:

* The file must name an engagement, an authorizer, and an expiry date.
* A run is refused outright once ``authorized_until`` has passed.
* A target is in scope only if it (or a resolved IP of it) matches a
  ``targets`` entry and does **not** match any ``exclude`` entry.
"""
from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable


class ScopeError(Exception):
    """Raised when a scope file is missing, invalid, or expired."""


@dataclass
class AuthorizationResult:
    spec: str
    authorized: bool
    ip: str | None = None
    reason: str = ""


@dataclass
class Scope:
    engagement: str
    authorized_by: str
    authorized_until: date
    targets: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    defaults: dict[str, Any] = field(default_factory=dict)
    source_path: str | None = None

    # --- internal, precomputed matchers -------------------------------------
    _target_nets: list[ipaddress._BaseNetwork] = field(default_factory=list, repr=False)
    _target_hosts: set[str] = field(default_factory=set, repr=False)
    _exclude_nets: list[ipaddress._BaseNetwork] = field(default_factory=list, repr=False)
    _exclude_hosts: set[str] = field(default_factory=set, repr=False)

    # ------------------------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        p = Path(path)
        if not p.exists():
            raise ScopeError(f"scope file not found: {p}")
        raw = _parse_structured(p)
        return cls.from_dict(raw, source_path=str(p))

    @classmethod
    def from_dict(cls, raw: dict[str, Any], source_path: str | None = None) -> "Scope":
        for required in ("engagement", "authorized_by", "authorized_until", "targets"):
            if not raw.get(required):
                raise ScopeError(
                    f"scope is missing required field '{required}'. "
                    "A scope must document what is authorized, by whom, and until when."
                )

        until = _parse_date(raw["authorized_until"])
        targets = [str(t).strip() for t in raw.get("targets", []) if str(t).strip()]
        exclude = [str(t).strip() for t in raw.get("exclude", []) if str(t).strip()]

        scope = cls(
            engagement=str(raw["engagement"]),
            authorized_by=str(raw["authorized_by"]),
            authorized_until=until,
            targets=targets,
            exclude=exclude,
            defaults=dict(raw.get("defaults", {}) or {}),
            source_path=source_path,
        )
        scope._compile()
        scope._validate_not_expired()
        return scope

    # ------------------------------------------------------------------------
    def _compile(self) -> None:
        for entry in self.targets:
            net, host = _classify(entry)
            if net is not None:
                self._target_nets.append(net)
            if host is not None:
                self._target_hosts.add(host)
        for entry in self.exclude:
            net, host = _classify(entry)
            if net is not None:
                self._exclude_nets.append(net)
            if host is not None:
                self._exclude_hosts.add(host)

    def _validate_not_expired(self) -> None:
        if self.authorized_until < date.today():
            raise ScopeError(
                f"engagement authorization expired on {self.authorized_until.isoformat()}. "
                "Refusing to run. Update 'authorized_until' with fresh written authorization."
            )

    # ------------------------------------------------------------------------
    def authorize(self, spec: str) -> AuthorizationResult:
        """Decide whether `spec` may be probed, resolving hostnames as needed."""
        spec = spec.strip()
        if not spec:
            return AuthorizationResult(spec, False, reason="empty target")

        # Literal hostname allow-listing (case-insensitive).
        host_key = spec.lower()
        excluded_by_host = host_key in self._exclude_hosts

        ip = _resolve(spec)

        # Exclusions win over inclusions, always.
        if excluded_by_host:
            return AuthorizationResult(spec, False, ip, "explicitly excluded by hostname")
        if ip is not None and self._ip_excluded(ip):
            return AuthorizationResult(spec, False, ip, "resolved IP is excluded from scope")

        # Inclusion: literal host match, or resolved-IP-in-network match.
        if host_key in self._target_hosts:
            return AuthorizationResult(spec, True, ip, "matches authorized hostname")
        if ip is not None and self._ip_in_targets(ip):
            return AuthorizationResult(spec, True, ip, "resolved IP within authorized scope")

        return AuthorizationResult(
            spec, False, ip,
            "not within any authorized target range — refusing to probe",
        )

    def filter_authorized(self, specs: Iterable[str]) -> tuple[list[AuthorizationResult], list[AuthorizationResult]]:
        allowed, denied = [], []
        for s in specs:
            res = self.authorize(s)
            (allowed if res.authorized else denied).append(res)
        return allowed, denied

    # --- helpers ------------------------------------------------------------
    def _ip_in_targets(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self._target_nets)

    def _ip_excluded(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self._exclude_nets)

    def summary(self) -> dict[str, Any]:
        return {
            "engagement": self.engagement,
            "authorized_by": self.authorized_by,
            "authorized_until": self.authorized_until.isoformat(),
            "targets": list(self.targets),
            "exclude": list(self.exclude),
            "source": self.source_path,
        }

    def banner(self) -> str:
        return (
            "=" * 70 + "\n"
            f"  ENGAGEMENT : {self.engagement}\n"
            f"  AUTHORIZED : {self.authorized_by}\n"
            f"  VALID UNTIL: {self.authorized_until.isoformat()}\n"
            f"  IN SCOPE   : {', '.join(self.targets) or '(none)'}\n"
            + ("  EXCLUDED   : " + ', '.join(self.exclude) + "\n" if self.exclude else "")
            + "  Authorized testing only. You are responsible for staying within scope.\n"
            + "=" * 70
        )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------
def _parse_structured(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ModuleNotFoundError:
            data = _try_json_fallback(text)
            if data is not None:
                return data
            raise ScopeError(
                "this scope is YAML but PyYAML is not installed. "
                "Install it (`pip install pyyaml`) or use a JSON scope file."
            )
        else:
            return yaml.safe_load(text) or {}
    # default: JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ScopeError(f"could not parse scope file as JSON: {exc}") from exc


def _try_json_fallback(text: str) -> dict[str, Any] | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _parse_date(value: Any) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    s = str(value).strip()
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    raise ScopeError(f"could not parse 'authorized_until' date: {value!r} (use YYYY-MM-DD)")


def _classify(entry: str) -> tuple[ipaddress._BaseNetwork | None, str | None]:
    """Classify a scope entry as an IP/CIDR network and/or a hostname.

    Returns (network, hostname). A bare IP becomes a /32 (or /128) network.
    A CIDR becomes a network. Anything else is treated as a hostname.
    """
    entry = entry.strip()
    # CIDR?
    if "/" in entry:
        try:
            return ipaddress.ip_network(entry, strict=False), None
        except ValueError:
            return None, entry.lower()
    # Bare IP?
    try:
        addr = ipaddress.ip_address(entry)
        return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}"), None
    except ValueError:
        return None, entry.lower()


def _resolve(spec: str) -> str | None:
    """Resolve a hostname/IP to a single IP string, or None on failure.

    Prefers IPv4 for determinism, but falls back to IPv6 when a host is
    AAAA-only. Both are matched against the scope's networks.
    """
    try:
        ipaddress.ip_address(spec)
        return spec
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(spec, None)
    except (socket.gaierror, OSError):
        return None
    v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    if v4:
        return v4[0]
    v6 = [i[4][0] for i in infos if i[0] == socket.AF_INET6]
    return v6[0] if v6 else None

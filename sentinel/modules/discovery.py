"""Host discovery (liveness) via TCP probes.

Raw ICMP ping needs elevated privileges and is often filtered, so Sentinel
infers liveness from TCP behaviour: if a probe to any common port either
connects or is actively refused, a host is present and responding.
"""
from __future__ import annotations

import socket

from sentinel.core.models import Finding, Severity, Target
from sentinel.modules.base import AuditModule, ModuleContext, register

PROBE_PORTS = [443, 80, 22, 445, 3389, 8080]


def _probe(ip: str, port: int, timeout: float) -> str | None:
    """Return 'open'/'refused' if the host clearly exists, else None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((ip, port))
        if rc == 0:
            return "open"
        # ECONNREFUSED means the host is up but the port is closed.
        if rc in (111, 10061):  # errno ECONNREFUSED on Linux / Windows
            return "refused"
        return None
    except OSError:
        return None
    finally:
        s.close()


@register
class DiscoveryModule(AuditModule):
    name = "discovery"
    description = "Determine whether a host is alive using TCP probes"

    def run(self, target: Target, ctx: ModuleContext) -> list[Finding]:
        ip = target.ip or target.spec
        signals: dict[int, str] = {}
        for port in PROBE_PORTS:
            res = _probe(ip, port, ctx.timeout)
            if res:
                signals[port] = res
                break  # one clear signal is enough to call it alive

        if signals:
            port, kind = next(iter(signals.items()))
            return [self.finding(
                target, "Host is alive",
                severity=Severity.INFO,
                detail=f"Responded on port {port} ({kind}).",
                evidence={"ip": ip, "signal_port": port, "signal": kind},
            )]
        return [self.finding(
            target, "Host did not respond to TCP probes",
            severity=Severity.INFO,
            detail="No response on common ports; host may be down or filtering all probes.",
            evidence={"ip": ip, "probed_ports": PROBE_PORTS},
        )]

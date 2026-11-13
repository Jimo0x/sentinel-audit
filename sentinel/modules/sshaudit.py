"""SSH service audit (non-intrusive).

Reads the SSH identification string the server sends on connect (e.g.
``SSH-2.0-OpenSSH_8.9p1``) and reports the protocol and implementation version,
flagging the obsolete SSH-1 protocol and notably old OpenSSH releases. It does
not authenticate, negotiate keys, or attempt any login.
"""
from __future__ import annotations

import re
import socket

from sentinel.core.models import Finding, Severity, Target
from sentinel.modules.base import AuditModule, ModuleContext, register
from sentinel.modules.portscan import check_port

SSH_PORTS = [22, 2222]
_OPENSSH_RE = re.compile(r"openssh[_-](\d+)\.(\d+)", re.IGNORECASE)
# A conservative "old" threshold; below this, flag for review.
OPENSSH_MIN_RECOMMENDED = (8, 0)


def _read_banner(ip: str, port: int, timeout: float) -> str | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
            line = data.decode("utf-8", "replace").splitlines()[0].strip() if data else ""
            return line or None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


@register
class SSHAuditModule(AuditModule):
    name = "sshaudit"
    description = "Audit SSH identification string: protocol and version posture"

    def run(self, target: Target, ctx: ModuleContext) -> list[Finding]:
        ip = target.ip or target.spec
        findings: list[Finding] = []
        ports = [p for p in SSH_PORTS if check_port(ip, p, ctx.timeout)]
        if not ports:
            return [self.finding(target, "No SSH service detected", severity=Severity.INFO)]

        for port in ports:
            banner = _read_banner(ip, port, ctx.timeout)
            if not banner or not banner.upper().startswith("SSH-"):
                findings.append(self.finding(
                    target, f"Port {port} open but no SSH banner", severity=Severity.INFO,
                    evidence={"port": port, "banner": banner}))
                continue

            proto = banner.split("-")[1] if "-" in banner else "?"
            findings.append(self.finding(
                target, f"SSH service on {port}: {banner}", severity=Severity.INFO,
                detail=f"Protocol {proto}.", evidence={"port": port, "banner": banner}))

            if proto.startswith("1."):
                findings.append(self.finding(
                    target, f"Obsolete SSH-1 protocol on port {port}", severity=Severity.HIGH,
                    detail="SSH protocol 1 is cryptographically broken.",
                    recommendation="Disable SSH-1; allow protocol 2 only.",
                    evidence={"port": port, "banner": banner}))

            m = _OPENSSH_RE.search(banner)
            if m:
                ver = (int(m.group(1)), int(m.group(2)))
                if ver < OPENSSH_MIN_RECOMMENDED:
                    findings.append(self.finding(
                        target, f"Potentially outdated OpenSSH {ver[0]}.{ver[1]} on port {port}",
                        severity=Severity.MEDIUM,
                        detail="Version is older than the recommended baseline; may miss security fixes.",
                        recommendation="Review against vendor advisories and update if end-of-life.",
                        evidence={"port": port, "version": f"{ver[0]}.{ver[1]}"}))
            # Version banner disclosure hygiene
            findings.append(self.finding(
                target, f"SSH version disclosed on port {port}", severity=Severity.LOW,
                detail="Implementation/version is advertised in the banner.",
                recommendation="Optionally set DebianBanner/no version disclosure to reduce fingerprinting.",
                evidence={"port": port, "banner": banner}))
        return findings

"""Service & version enumeration via banner grabbing.

For each open port we read whatever the service announces (many protocols send
a banner on connect), and for HTTP-ish ports we issue a minimal request to coax
out a Server header. This is lightweight fingerprinting, not exploitation.
"""
from __future__ import annotations

import socket

from sentinel.core.models import Finding, Severity, Target
from sentinel.modules.base import AuditModule, ModuleContext, register
from sentinel.modules.portscan import WELL_KNOWN, parse_ports

HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888, 3000, 5000, 9000, 9090}


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Connect and read a short banner, nudging HTTP services with a request."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in HTTP_PORTS:
                req = (
                    f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n"
                    "User-Agent: sentinel-audit/0.1\r\n\r\n"
                )
                try:
                    s.sendall(req.encode())
                except OSError:
                    pass
            try:
                data = s.recv(2048)
            except socket.timeout:
                data = b""
            return data.decode("utf-8", errors="replace").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""


def _server_header(banner: str) -> str | None:
    for line in banner.splitlines():
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    return None


@register
class ServicesModule(AuditModule):
    name = "services"
    description = "Grab banners and fingerprint services on open ports"

    def run(self, target: Target, ctx: ModuleContext) -> list[Finding]:
        ip = target.ip or target.spec
        ports = parse_ports(ctx.ports)
        findings: list[Finding] = []

        for port in ports:
            if not ctx.is_open(ip, port):
                continue
            banner = grab_banner(ip, port, ctx.timeout)
            svc = WELL_KNOWN.get(port, "unknown")
            if not banner:
                findings.append(self.finding(
                    target, f"Open port {port}/{svc} (no banner)",
                    severity=Severity.INFO,
                    evidence={"port": port, "service": svc},
                ))
                continue

            server = _server_header(banner)
            first_line = banner.splitlines()[0] if banner.splitlines() else banner
            summary = server or first_line[:120]
            findings.append(self.finding(
                target, f"{svc} on {port}: {summary}",
                severity=Severity.INFO,
                detail=f"Banner/first line: {first_line[:200]}",
                evidence={"port": port, "service": svc,
                          "server_header": server, "banner": banner[:500]},
            ))

            # Version-disclosure hygiene flag (informational → low).
            if server and any(ch.isdigit() for ch in server):
                findings.append(self.finding(
                    target, f"Service version disclosed on port {port}",
                    severity=Severity.LOW,
                    detail=f"Server header reveals version detail: {server}",
                    recommendation="Suppress or genericize version banners to reduce fingerprinting.",
                    evidence={"port": port, "server_header": server},
                ))
        if not findings:
            findings.append(self.finding(
                target, "No enumerable services found",
                severity=Severity.INFO,
            ))
        return findings

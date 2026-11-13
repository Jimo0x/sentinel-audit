"""TCP connect port scanner.

Uses full TCP connect() scans (not raw SYN) so it needs no special privileges
and works identically on Linux and Windows. Concurrency is bounded by a thread
pool sized from the module context.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from sentinel.core.models import Finding, Severity, Target
from sentinel.modules.base import AuditModule, ModuleContext, register
from sentinel.modules._netutil import tcp_open

# Backwards-compatible alias: a bare TCP-open probe.
check_port = tcp_open

# A pragmatic "top ports" list covering the services you meet most often.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 631, 636, 993, 995, 1025, 1433, 1521, 1723, 2049, 2375, 2376,
    3000, 3306, 3389, 5000, 5432, 5601, 5900, 5985, 5986, 6379, 7001, 8000,
    8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 27017,
]

# Service names for nicer output, independent of /etc/services availability.
WELL_KNOWN = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 2375: "docker", 2376: "docker-tls", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 5985: "winrm", 5986: "winrm-tls",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}


def parse_ports(spec: str) -> list[int]:
    """Parse a port spec: 'common', 'full', '1-1024', or '22,80,443'."""
    spec = (spec or "common").strip().lower()
    if spec == "common":
        return sorted(COMMON_PORTS)
    if spec == "full":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


@register
class PortScanModule(AuditModule):
    name = "portscan"
    description = "Concurrent TCP connect scan to find listening services"

    def run(self, target: Target, ctx: ModuleContext) -> list[Finding]:
        ip = target.ip or target.spec
        ports = parse_ports(ctx.ports)
        open_ports: list[int] = []

        # Probe through the shared cache so results are reused by later modules.
        workers = max(1, min(ctx.concurrency, len(ports)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(ctx.is_open, ip, p): p for p in ports}
            for fut in as_completed(futures):
                if fut.result():
                    open_ports.append(futures[fut])

        open_ports.sort()
        findings: list[Finding] = []
        if not open_ports:
            return [self.finding(
                target, "No open TCP ports found in scanned set",
                severity=Severity.INFO,
                detail=f"Scanned {len(ports)} port(s); none responded.",
            )]

        # One summary finding plus per-port detail for notable services.
        named = {p: WELL_KNOWN.get(p, "unknown") for p in open_ports}
        findings.append(self.finding(
            target, f"{len(open_ports)} open TCP port(s)",
            severity=Severity.INFO,
            detail=", ".join(f"{p}/{named[p]}" for p in open_ports),
            evidence={"open_ports": open_ports, "services": named},
        ))

        # Flag some commonly risky exposures.
        risky = {
            23: ("Telnet exposed", Severity.HIGH, "Telnet is cleartext; prefer SSH and disable Telnet."),
            2375: ("Unauthenticated Docker API likely exposed", Severity.CRITICAL,
                   "Port 2375 is the unencrypted Docker API; restrict it or require TLS (2376)."),
            6379: ("Redis exposed", Severity.HIGH, "Ensure Redis requires auth and is not reachable from untrusted networks."),
            11211: ("Memcached exposed", Severity.HIGH, "Memcached has no auth; never expose it to untrusted networks."),
            3389: ("RDP exposed", Severity.MEDIUM, "Restrict RDP to VPN / jump hosts; enable NLA and MFA."),
            445: ("SMB exposed", Severity.MEDIUM, "Restrict SMB exposure; ensure patching and signing."),
        }
        for port, (title, sev, rec) in risky.items():
            if port in open_ports:
                findings.append(self.finding(
                    target, title, severity=sev,
                    detail=f"Port {port}/{named[port]} is reachable.",
                    recommendation=rec,
                    evidence={"port": port},
                ))
        return findings

"""TLS / certificate configuration audit.

Inspects the certificate (validity window, subject, issuer, self-signed status)
and the negotiated protocol version, flagging deprecated protocols and expiring
or expired certificates.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from sentinel.core.models import Finding, Severity, Target
from sentinel.modules.base import AuditModule, ModuleContext, register
from sentinel.modules.portscan import check_port

TLS_PORTS = [443, 8443, 993, 995, 465, 636, 990, 989, 5986]

# Protocols considered deprecated/insecure.
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _parse_cert_time(value: str) -> datetime | None:
    # OpenSSL format e.g. "Jun  1 12:00:00 2026 GMT"
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _negotiated(ip: str, port: int, server_name: str, timeout: float) -> tuple[str | None, str | None]:
    """Return (protocol_version, cipher_name) without requiring a valid cert."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name) as ss:
                cipher = ss.cipher()
                return ss.version(), (cipher[0] if cipher else None)
    except (ssl.SSLError, socket.timeout, OSError):
        return None, None


# Protocol versions to probe individually, with the severity of supporting each.
_PROTO_PROBES = [
    ("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None), Severity.CRITICAL),
    ("TLSv1", ssl.TLSVersion.TLSv1, Severity.HIGH),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, Severity.HIGH),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, Severity.INFO),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, Severity.INFO),
]


def _supports_protocol(ip: str, port: int, server_name: str, tls_version, timeout: float) -> bool:
    """Attempt a handshake restricted to exactly one TLS version."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
    except (ValueError, OSError):
        # This Python/OpenSSL build cannot pin to this version (often the case
        # for the deprecated ones) — treat as "cannot test / not supported".
        return False
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name):
                return True
    except (ssl.SSLError, socket.timeout, OSError):
        return False


def enumerate_protocols(ip: str, port: int, server_name: str, timeout: float) -> list[tuple[str, bool, Severity]]:
    """Return [(version_name, supported, severity_if_supported), ...]."""
    out = []
    for name, version, sev in _PROTO_PROBES:
        if version is None:
            continue
        out.append((name, _supports_protocol(ip, port, server_name, version, timeout), sev))
    return out


def _verified_cert(ip: str, port: int, server_name: str, timeout: float):
    """Return (cert_dict_or_None, validation_error_or_None)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name) as ss:
                return ss.getpeercert(), None
    except ssl.SSLCertVerificationError as exc:
        return None, f"certificate validation failed: {exc.verify_message or exc}"
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


@register
class TLSAuditModule(AuditModule):
    name = "tls"
    description = "Audit TLS protocol versions and certificate validity"

    def run(self, target: Target, ctx: ModuleContext) -> list[Finding]:
        ip = target.ip or target.spec
        server_name = target.hostname or target.spec
        findings: list[Finding] = []

        tls_ports = [p for p in TLS_PORTS if check_port(ip, p, ctx.timeout)]
        if not tls_ports:
            return [self.finding(
                target, "No TLS services detected",
                severity=Severity.INFO,
                detail=f"None of the common TLS ports responded: {TLS_PORTS}",
            )]

        for port in tls_ports:
            version, cipher = _negotiated(ip, port, server_name, ctx.timeout)
            if version is None:
                findings.append(self.finding(
                    target, f"TLS handshake failed on port {port}",
                    severity=Severity.LOW,
                    detail="Port is open but a TLS handshake could not be completed.",
                    evidence={"port": port},
                ))
                continue

            sev = Severity.HIGH if version in WEAK_PROTOCOLS else Severity.INFO
            findings.append(self.finding(
                target, f"TLS {version} negotiated on port {port}",
                severity=sev,
                detail=f"Cipher: {cipher}",
                recommendation=("Disable deprecated protocols; require TLS 1.2+."
                                if sev >= Severity.HIGH else ""),
                evidence={"port": port, "protocol": version, "cipher": cipher},
            ))

            # Enumerate which protocol versions the server will accept.
            supported = enumerate_protocols(ip, port, server_name, ctx.timeout)
            accepted = [name for name, ok, _ in supported if ok]
            if accepted:
                findings.append(self.finding(
                    target, f"Supported TLS versions on port {port}",
                    severity=Severity.INFO,
                    detail=", ".join(accepted),
                    evidence={"port": port, "supported": accepted}))
            for name, ok, sev in supported:
                if ok and sev >= Severity.HIGH:
                    findings.append(self.finding(
                        target, f"Deprecated {name} accepted on port {port}",
                        severity=sev,
                        detail=f"The server completes a handshake using {name}.",
                        recommendation="Disable this protocol; require TLS 1.2+ (prefer 1.3).",
                        evidence={"port": port, "protocol": name}))

            cert, err = _verified_cert(ip, port, server_name, ctx.timeout)
            if err:
                findings.append(self.finding(
                    target, f"Certificate validation issue on port {port}",
                    severity=Severity.MEDIUM,
                    detail=err,
                    recommendation="Install a certificate trusted for this hostname (correct SAN, valid chain).",
                    evidence={"port": port},
                ))
                continue

            findings.extend(self._audit_cert(target, port, cert))
        return findings

    def _audit_cert(self, target: Target, port: int, cert: dict) -> list[Finding]:
        out: list[Finding] = []
        subject = dict(x[0] for x in cert.get("subject", ())) if cert.get("subject") else {}
        issuer = dict(x[0] for x in cert.get("issuer", ())) if cert.get("issuer") else {}
        cn = subject.get("commonName", "?")
        not_after = cert.get("notAfter")
        exp = _parse_cert_time(not_after) if not_after else None

        info = {"port": port, "common_name": cn,
                "issuer": issuer.get("commonName") or issuer.get("organizationName"),
                "not_after": not_after}

        if exp:
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                out.append(self.finding(
                    target, f"Certificate EXPIRED on port {port}",
                    severity=Severity.HIGH,
                    detail=f"{cn} expired {abs(days)} day(s) ago ({not_after}).",
                    recommendation="Renew the certificate immediately.",
                    evidence=info,
                ))
            elif days < 21:
                out.append(self.finding(
                    target, f"Certificate expiring soon on port {port}",
                    severity=Severity.MEDIUM,
                    detail=f"{cn} expires in {days} day(s) ({not_after}).",
                    recommendation="Renew before expiry; automate renewal if possible.",
                    evidence=info,
                ))
            else:
                out.append(self.finding(
                    target, f"Certificate valid on port {port}",
                    severity=Severity.INFO,
                    detail=f"{cn}, expires in {days} day(s).",
                    evidence=info,
                ))
        else:
            out.append(self.finding(
                target, f"Certificate present on port {port}",
                severity=Severity.INFO,
                detail=f"Subject CN: {cn}",
                evidence=info,
            ))
        return out

"""HTTP response hardening audit.

Fetches response headers and checks for the security headers a hardened web
service should set, plus common information-leak and cookie-flag issues. Uses an
unverified TLS context on purpose: the goal is to read the server's *configuration*,
not to trust it.
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from sentinel.core.models import Finding, Severity, Target
from sentinel.modules.base import AuditModule, ModuleContext, register

# port -> scheme
WEB_PORTS = {80: "http", 8080: "http", 8000: "http", 8888: "http",
             3000: "http", 5000: "http", 443: "https", 8443: "https"}

# header -> (severity if missing, recommendation)
EXPECTED_HEADERS = {
    "strict-transport-security": (Severity.MEDIUM, "Add HSTS (Strict-Transport-Security) to force HTTPS."),
    "content-security-policy": (Severity.MEDIUM, "Define a Content-Security-Policy to mitigate XSS/injection."),
    "x-content-type-options": (Severity.LOW, "Set X-Content-Type-Options: nosniff."),
    "x-frame-options": (Severity.LOW, "Set X-Frame-Options or a CSP frame-ancestors directive to prevent clickjacking."),
    "referrer-policy": (Severity.LOW, "Set a Referrer-Policy (e.g. strict-origin-when-cross-origin)."),
}


def _fetch_headers(url: str, timeout: float):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "sentinel-audit/0.1"})
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    with opener.open(req, timeout=timeout) as resp:
        return resp.status, dict(resp.headers.items())


@register
class HTTPAuditModule(AuditModule):
    name = "http"
    description = "Audit HTTP security headers, server leakage, and cookie flags"

    def run(self, target: Target, ctx: ModuleContext) -> list[Finding]:
        ip = target.ip or target.spec
        host = target.hostname or target.spec
        findings: list[Finding] = []

        open_web = {p: s for p, s in WEB_PORTS.items() if ctx.is_open(ip, p)}
        if not open_web:
            return [self.finding(
                target, "No HTTP(S) services detected",
                severity=Severity.INFO,
            )]

        for port, scheme in sorted(open_web.items()):
            netloc = host if port in (80, 443) else f"{host}:{port}"
            url = f"{scheme}://{netloc}/"
            try:
                status, headers = _fetch_headers(url, ctx.timeout)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                findings.append(self.finding(
                    target, f"HTTP request failed on port {port}",
                    severity=Severity.INFO,
                    detail=f"{url}: {exc}",
                    evidence={"url": url},
                ))
                continue

            lower = {k.lower(): v for k, v in headers.items()}
            findings.append(self.finding(
                target, f"HTTP {status} from {url}",
                severity=Severity.INFO,
                detail="Headers audited for hardening.",
                evidence={"url": url, "status": status, "server": lower.get("server")},
            ))

            # Missing security headers
            for header, (sev, rec) in EXPECTED_HEADERS.items():
                if header == "strict-transport-security" and scheme != "https":
                    continue
                if header not in lower:
                    findings.append(self.finding(
                        target, f"Missing header: {header}",
                        severity=sev,
                        detail=f"{url} does not set {header}.",
                        recommendation=rec,
                        cwe="CWE-693", owasp="A05:2021 Security Misconfiguration",
                        evidence={"url": url, "header": header},
                    ))

            # Server / tech version disclosure
            server = lower.get("server")
            if server and any(c.isdigit() for c in server):
                findings.append(self.finding(
                    target, "Server version disclosed in HTTP header",
                    severity=Severity.LOW,
                    detail=f"Server: {server}",
                    recommendation="Suppress or genericize the Server header.",
                    evidence={"url": url, "server": server},
                ))
            for leak in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
                if leak in lower:
                    findings.append(self.finding(
                        target, f"Technology disclosure via {leak}",
                        severity=Severity.LOW,
                        detail=f"{leak}: {lower[leak]}",
                        recommendation=f"Remove the {leak} header.",
                        evidence={"url": url, "header": leak, "value": lower[leak]},
                    ))

            # Cookie flags
            set_cookie = headers.get("Set-Cookie")
            if set_cookie:
                flags = set_cookie.lower()
                missing = [f for f in ("secure", "httponly") if f not in flags]
                if scheme == "https" and "secure" in missing:
                    findings.append(self.finding(
                        target, "Cookie without Secure flag over HTTPS",
                        severity=Severity.MEDIUM,
                        detail="A Set-Cookie response lacks the Secure attribute.",
                        recommendation="Add Secure (and HttpOnly, SameSite) to session cookies.",
                        evidence={"url": url},
                    ))
                elif "httponly" in missing:
                    findings.append(self.finding(
                        target, "Cookie without HttpOnly flag",
                        severity=Severity.LOW,
                        detail="A Set-Cookie response lacks HttpOnly.",
                        recommendation="Add HttpOnly to cookies not needed by JavaScript.",
                        evidence={"url": url},
                    ))
        return findings

"""Exposure & misconfiguration audit for web servers / apps.

Non-destructive checks for things that routinely show up in real assessments:
accidentally exposed sensitive files (.git, .env, backups), directory listing,
permissive HTTP methods, and over-broad CORS. Every check is a plain GET/OPTIONS
request — nothing is modified, injected, or brute-forced.

A curated, deliberately small path list keeps request volume low and polite.
"""
from __future__ import annotations

from urllib.parse import urlparse

from sentinel.core.models import Finding, Severity, Target
from sentinel.modules._http import fetch
from sentinel.modules.base import AuditModule, ModuleContext, register
from sentinel.modules.http_audit import WEB_PORTS

# path -> (label, severity, signature substring to confirm it's really the file)
SENSITIVE_PATHS: dict[str, tuple[str, Severity, str | None]] = {
    "/.git/config": ("Exposed .git repository config", Severity.CRITICAL, "[core]"),
    "/.git/HEAD": ("Exposed .git repository", Severity.CRITICAL, "ref:"),
    "/.env": ("Exposed .env file (likely secrets)", Severity.CRITICAL, "="),
    "/.env.local": ("Exposed .env.local file", Severity.CRITICAL, "="),
    "/config.php.bak": ("Exposed PHP config backup", Severity.HIGH, None),
    "/wp-config.php.bak": ("Exposed WordPress config backup", Severity.CRITICAL, None),
    "/.htpasswd": ("Exposed .htpasswd", Severity.HIGH, ":"),
    "/.svn/entries": ("Exposed Subversion metadata", Severity.HIGH, None),
    "/.DS_Store": ("Exposed .DS_Store (directory listing leak)", Severity.LOW, None),
    "/backup.zip": ("Exposed backup archive", Severity.HIGH, None),
    "/backup.sql": ("Exposed database dump", Severity.CRITICAL, None),
    "/server-status": ("Apache server-status exposed", Severity.MEDIUM, "Apache Server Status"),
    "/phpinfo.php": ("phpinfo() exposed", Severity.HIGH, "phpinfo()"),
    "/web.config": ("Exposed web.config", Severity.MEDIUM, "<configuration"),
    "/actuator/env": ("Spring Boot actuator/env exposed", Severity.CRITICAL, "propertySources"),
    "/actuator/health": ("Spring Boot actuator exposed", Severity.LOW, "status"),
    "/.aws/credentials": ("Exposed AWS credentials file", Severity.CRITICAL, "aws_access_key_id"),
    "/swagger.json": ("API schema (swagger.json) exposed", Severity.INFO, "swagger"),
    "/api-docs": ("API docs exposed", Severity.INFO, None),
}

DIR_LISTING_PATHS = ["/", "/images/", "/uploads/", "/files/", "/backup/", "/static/"]
INTERESTING_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


def _base_url(ctx: ModuleContext, ip: str, host: str) -> str | None:
    for port, scheme in sorted(WEB_PORTS.items(), key=lambda kv: 0 if kv[1] == "https" else 1):
        if ctx.is_open(ip, port):
            netloc = host if port in (80, 443) else f"{host}:{port}"
            return f"{scheme}://{netloc}"
    return None


@register
class ExposureModule(AuditModule):
    name = "exposure"
    description = "Find exposed sensitive files, dir listing, risky methods, broad CORS"

    def run(self, target: Target, ctx: ModuleContext) -> list[Finding]:
        ip = target.ip or target.spec
        host = target.hostname or target.spec
        base = _base_url(ctx, ip, host)
        if not base:
            return [self.finding(target, "No web service for exposure checks", severity=Severity.INFO)]

        findings: list[Finding] = []
        findings += self._sensitive_files(target, base, ctx)
        findings += self._dir_listing(target, base, ctx)
        findings += self._methods(target, base, ctx)
        findings += self._cors(target, base, ctx)
        if not findings:
            findings.append(self.finding(target, "No exposure issues detected", severity=Severity.INFO))
        return findings

    def _sensitive_files(self, target, base, ctx) -> list[Finding]:
        timeout = ctx.timeout
        out = []
        # Baseline probe: a path that should not exist. If it still returns 200,
        # the server has a catch-all / soft-404, so a bare 200 means nothing —
        # we then require either a signature match or a body that differs from
        # the baseline before flagging anything.
        ctx.throttle()
        baseline = fetch(base + "/sentinel-nonexistent-a9f3c1e7", timeout=timeout)
        soft_200 = baseline.status == 200
        baseline_body = baseline.body if soft_200 else b""

        for path, (label, sev, sig) in SENSITIVE_PATHS.items():
            ctx.throttle()
            resp = fetch(base + path, timeout=timeout)
            if resp.status != 200 or not resp.body:
                continue
            text = resp.text[:4000]
            sig_match = sig is not None and sig.lower() in text.lower()

            if soft_200:
                # Only trust a signature match, or a body clearly different from
                # the catch-all page, to avoid false positives.
                differs = resp.body != baseline_body and abs(len(resp.body) - len(baseline_body)) > 16
                if not (sig_match or (sig is None and differs)):
                    continue
                confidence = "signature matched" if sig_match else "content differs from catch-all page"
            else:
                if sig is not None and not sig_match:
                    out.append(self.finding(
                        target, f"{path} returned 200 (verify)", severity=Severity.LOW,
                        detail="Accessible but expected content signature not found.",
                        evidence={"url": base + path}))
                    continue
                confidence = "signature matched" if sig_match else "returned 200 (server has normal 404s)"

            out.append(self.finding(
                target, label, severity=sev,
                detail=f"{base + path} exposed — {confidence}.",
                recommendation="Remove the file from the web root or block access; rotate any leaked secrets.",
                evidence={"url": base + path, "status": resp.status, "confidence": confidence}))
        return out

    def _dir_listing(self, target, base, ctx) -> list[Finding]:
        timeout = ctx.timeout
        out = []
        for path in DIR_LISTING_PATHS:
            ctx.throttle()
            resp = fetch(base + path, timeout=timeout)
            if resp.status == 200 and ("Index of /" in resp.text or "<title>Directory listing for" in resp.text):
                out.append(self.finding(
                    target, f"Directory listing enabled: {path}", severity=Severity.MEDIUM,
                    detail=f"{base + path} returns an auto-generated index.",
                    recommendation="Disable automatic directory indexing.",
                    evidence={"url": base + path}))
        return out

    def _methods(self, target, base, ctx) -> list[Finding]:
        timeout = ctx.timeout
        resp = fetch(base + "/", timeout=timeout, method="OPTIONS")
        allow = resp.header("allow")
        if not allow:
            return []
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = sorted(methods & INTERESTING_METHODS)
        out = [self.finding(target, "Allowed HTTP methods", severity=Severity.INFO,
                            detail=allow, evidence={"methods": sorted(methods)})]
        if risky:
            sev = Severity.HIGH if {"PUT", "DELETE"} & set(risky) else Severity.MEDIUM
            out.append(self.finding(
                target, f"Potentially risky HTTP methods: {', '.join(risky)}", severity=sev,
                detail="Server advertises write/diagnostic methods.",
                recommendation="Disable methods the application does not require (esp. PUT/DELETE/TRACE).",
                evidence={"methods": risky}))
        return out

    def _cors(self, target, base, ctx) -> list[Finding]:
        timeout = ctx.timeout
        probe = "https://sentinel-cors-probe.example"
        resp = fetch(base + "/", timeout=timeout, headers={"Origin": probe})
        acao = resp.header("access-control-allow-origin")
        acac = (resp.header("access-control-allow-credentials") or "").lower()
        if not acao:
            return []
        if acao == probe and acac == "true":
            return [self.finding(
                target, "Dangerous CORS: reflects arbitrary origin with credentials", severity=Severity.HIGH,
                detail=f"Access-Control-Allow-Origin reflected {probe} with Allow-Credentials: true.",
                recommendation="Never reflect arbitrary Origins with credentials; use an explicit allow-list.",
                evidence={"acao": acao, "acac": acac})]
        if acao == "*" and acac == "true":
            return [self.finding(
                target, "Invalid/over-broad CORS (* with credentials)", severity=Severity.MEDIUM,
                detail="Wildcard ACAO combined with credentials is insecure (and ignored by browsers).",
                recommendation="Use a specific origin allow-list for credentialed requests.",
                evidence={"acao": acao, "acac": acac})]
        if acao == probe or acao == "*":
            return [self.finding(
                target, "Permissive CORS policy", severity=Severity.LOW,
                detail=f"Access-Control-Allow-Origin: {acao}",
                recommendation="Restrict CORS to trusted origins if the endpoint serves sensitive data.",
                evidence={"acao": acao})]
        return []

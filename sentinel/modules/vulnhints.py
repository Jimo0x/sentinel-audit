"""Version-based risk surfacing (advisory, non-authoritative).

Reads software/version strings a service already advertises (HTTP Server header,
SSH identification string, service banners) and flags versions that are notably
old or end-of-life, pointing at the vendor's advisory page to verify.

IMPORTANT: this is a *hygiene hint*, not a vulnerability assertion. Banners can
be inaccurate, spoofed, or reflect back-ported security fixes, so every finding
says "verify" and links the vendor's security page. It performs no exploitation.
"""
from __future__ import annotations

import re

from sentinel.core.models import Finding, Severity, Target
from sentinel.modules.base import AuditModule, ModuleContext, register
from sentinel.modules._http import fetch
from sentinel.modules.http_audit import WEB_PORTS
from sentinel.modules.services import grab_banner
from sentinel.modules.sshaudit import _read_banner, SSH_PORTS

# product -> (regex capturing a dotted version, baseline (maj,min), advisory url, note)
RULES = [
    ("OpenSSH", re.compile(r"openssh[_-](\d+)\.(\d+)", re.I), (8, 5),
     "https://www.openssh.com/security.html",
     "OpenSSH releases below ~8.5 are dated; confirm the distro hasn't back-ported fixes."),
    ("Apache httpd", re.compile(r"apache/(\d+)\.(\d+)\.(\d+)", re.I), (2, 4),
     "https://httpd.apache.org/security/vulnerabilities_24.html",
     "Apache 2.2.x is end-of-life; 2.4.x before 2.4.52 had notable CVEs (e.g. path traversal)."),
    ("nginx", re.compile(r"nginx/(\d+)\.(\d+)\.(\d+)", re.I), (1, 22),
     "https://nginx.org/en/security_advisories.html",
     "nginx before 1.22 may miss recent fixes; verify the running build."),
    ("PHP", re.compile(r"php/(\d+)\.(\d+)", re.I), (8, 1),
     "https://www.php.net/supported-versions.php",
     "PHP 5.x/7.x are end-of-life and receive no security fixes."),
]


def _older(got: tuple[int, ...], baseline: tuple[int, int]) -> bool:
    return (got[0], got[1]) < baseline


def _check(text: str):
    """Yield (product, version_str, url, note) for each rule the text triggers."""
    for product, rx, baseline, url, note in RULES:
        m = rx.search(text or "")
        if not m:
            continue
        nums = tuple(int(x) for x in m.groups())
        if _older(nums, baseline):
            yield product, ".".join(str(n) for n in nums), url, note


@register
class VulnHintsModule(AuditModule):
    name = "vulnhints"
    description = "Flag potentially outdated software versions from banners (advisory)"

    def run(self, target: Target, ctx: ModuleContext) -> list[Finding]:
        ip = target.ip or target.spec
        host = target.hostname or target.spec
        banners: list[tuple[str, str]] = []   # (source, text)

        # HTTP Server headers
        for port, scheme in WEB_PORTS.items():
            if not ctx.is_open(ip, port):
                continue
            netloc = host if port in (80, 443) else f"{host}:{port}"
            resp = fetch(f"{scheme}://{netloc}/", timeout=ctx.timeout, method="HEAD")
            server = resp.header("server")
            if server:
                banners.append((f"HTTP:{port}", server))

        # SSH identification strings
        for port in SSH_PORTS:
            if ctx.is_open(ip, port):
                b = _read_banner(ip, port, ctx.timeout)
                if b:
                    banners.append((f"SSH:{port}", b))

        # Generic banners on a few common service ports
        for port in (21, 25, 110, 143):
            if ctx.is_open(ip, port):
                b = grab_banner(ip, port, ctx.timeout)
                if b:
                    banners.append((f"svc:{port}", b))

        findings: list[Finding] = []
        seen = set()
        for source, text in banners:
            for product, version, url, note in _check(text):
                key = (product, version)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self.finding(
                    target, f"Potentially outdated {product} {version} (verify)",
                    severity=Severity.LOW,
                    detail=f"{note} Seen via {source}: '{text[:120]}'.",
                    recommendation=f"Confirm the running version and patch level against {url}.",
                    cwe="CWE-1104", owasp="A06:2021 Vulnerable and Outdated Components",
                    references=[url],
                    evidence={"source": source, "product": product, "version": version}))

        if not findings:
            findings.append(self.finding(
                target, "No outdated-version hints from banners",
                severity=Severity.INFO,
                detail="No advertised versions matched the advisory baseline (absence is not proof of patching)."))
        return findings

"""Email security posture audit (SPF / DMARC / DKIM / MX) via DNS.

Purely DNS-based and read-only. Useful when auditing a domain's resistance to
spoofing and phishing. Reuses the dependency-free resolver from the dns module.
"""
from __future__ import annotations

import ipaddress

from sentinel.core.models import Finding, Severity, Target
from sentinel.modules.base import AuditModule, ModuleContext, register
from sentinel.modules.dns_enum import dns_query, _system_resolver, _FALLBACK_RESOLVERS

COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]


@register
class EmailSecModule(AuditModule):
    name = "emailsec"
    description = "Audit email anti-spoofing posture: SPF, DMARC, DKIM, MX"

    def run(self, target: Target, ctx: ModuleContext) -> list[Finding]:
        host = (target.hostname or target.spec).strip().lower()
        # Only meaningful for domain names.
        try:
            ipaddress.ip_address(host)
            return [self.finding(target, "Email security audit skipped (target is an IP, not a domain)",
                                 severity=Severity.INFO)]
        except ValueError:
            pass

        resolver = _system_resolver() or _FALLBACK_RESOLVERS[0]
        findings: list[Finding] = []

        # MX
        mx = dns_query(host, "MX", resolver, ctx.timeout)
        if mx:
            findings.append(self.finding(target, "MX records present", severity=Severity.INFO,
                                         detail="; ".join(mx[:10]), evidence={"mx": mx}))
        else:
            findings.append(self.finding(target, "No MX records", severity=Severity.INFO,
                                         detail="Domain may not receive email."))

        # SPF
        txt = dns_query(host, "TXT", resolver, ctx.timeout)
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        if not spf:
            findings.append(self.finding(
                target, "No SPF record", severity=Severity.MEDIUM,
                detail="No v=spf1 TXT record found.",
                recommendation="Publish an SPF record to declare authorized senders and reduce spoofing."))
        else:
            rec = spf[0]
            sev, note = Severity.INFO, "SPF present."
            if "+all" in rec.replace(" ", ""):
                sev, note = Severity.HIGH, "SPF ends with +all — allows anyone to send as this domain."
            elif "?all" in rec.replace(" ", ""):
                sev, note = Severity.LOW, "SPF uses ?all (neutral) — weak enforcement."
            findings.append(self.finding(
                target, "SPF record", severity=sev, detail=f"{note} ({rec[:180]})",
                recommendation=("Tighten SPF to -all (hard fail) once senders are verified."
                                if sev >= Severity.LOW else ""),
                evidence={"spf": rec}))

        # DMARC
        dmarc = dns_query(f"_dmarc.{host}", "TXT", resolver, ctx.timeout)
        dmarc_rec = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)
        if not dmarc_rec:
            findings.append(self.finding(
                target, "No DMARC record", severity=Severity.MEDIUM,
                detail="No _dmarc TXT policy found.",
                recommendation="Publish a DMARC record (start with p=none for monitoring, then enforce)."))
        else:
            policy = "none"
            for part in dmarc_rec.split(";"):
                if part.strip().lower().startswith("p="):
                    policy = part.split("=", 1)[1].strip().lower()
            sev = Severity.LOW if policy == "none" else Severity.INFO
            findings.append(self.finding(
                target, f"DMARC policy: p={policy}", severity=sev,
                detail=dmarc_rec[:180],
                recommendation=("Move beyond p=none to quarantine/reject once reports look clean."
                                if policy == "none" else ""),
                evidence={"dmarc": dmarc_rec}))

        # DKIM (best-effort selector probe)
        found_selectors = []
        for sel in COMMON_DKIM_SELECTORS:
            rec = dns_query(f"{sel}._domainkey.{host}", "TXT", resolver, ctx.timeout)
            if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in rec):
                found_selectors.append(sel)
        if found_selectors:
            findings.append(self.finding(
                target, f"DKIM selector(s) found: {', '.join(found_selectors)}", severity=Severity.INFO,
                evidence={"selectors": found_selectors}))
        else:
            findings.append(self.finding(
                target, "No DKIM selectors found (common names)", severity=Severity.INFO,
                detail="Did not find DKIM at common selectors; custom selectors can't be enumerated by name.",
                recommendation="Ensure DKIM signing is configured for all legitimate senders."))
        return findings

"""Import nmap XML (`nmap -oX`) into Sentinel's unified report model.

Lets you combine a privileged/advanced nmap scan with Sentinel's reporting,
diffing and gating. Parsing uses the standard-library XML parser in a hardened
mode (external entities disabled) because the XML is untrusted input.
"""
from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from sentinel.core.models import AuditReport, Finding, ModuleResult, Severity, Target
from sentinel.core.scope import Scope

# Service exposures worth elevating, mirroring the live portscan module.
_RISKY = {
    "telnet": (Severity.HIGH, "Telnet is cleartext; prefer SSH."),
    "ms-wbt-server": (Severity.MEDIUM, "Restrict RDP to VPN/jump hosts."),
    "microsoft-ds": (Severity.MEDIUM, "Restrict SMB exposure."),
    "redis": (Severity.HIGH, "Ensure Redis requires auth and is firewalled."),
    "memcached": (Severity.HIGH, "Memcached has no auth; never expose it."),
}


def _safe_parse(path: str | Path) -> ET.Element:
    parser = ET.XMLParser()
    # Defuse entity expansion on parsers that expose it.
    try:
        parser.parser.DefaultHandler = lambda data: None  # type: ignore[attr-defined]
    except Exception:
        pass
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ValueError("refusing to parse nmap XML containing a DOCTYPE/ENTITY declaration")
    return ET.fromstring(text)


def import_nmap(path: str | Path, scope: Scope | None = None) -> AuditReport:
    root = _safe_parse(path)
    report = AuditReport(
        engagement=f"nmap import ({Path(path).name})",
        authorized_by="imported from nmap XML",
    )
    denied: list[str] = []

    for host in root.findall("host"):
        addr_el = host.find("address")
        ip = addr_el.get("addr") if addr_el is not None else None
        if not ip:
            continue
        hostname = None
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")

        # Respect scope if one was supplied.
        if scope is not None:
            auth = scope.authorize(hostname or ip)
            if not auth.authorized:
                denied.append(f"{hostname or ip}: {auth.reason}")
                continue

        target = Target(spec=hostname or ip, ip=ip, hostname=hostname)
        report.targets.append(target)
        result = ModuleResult(module="nmap", target=target.display())

        open_ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port.get("portid"))
            svc = port.find("service")
            name = svc.get("name") if svc is not None else "unknown"
            product = (svc.get("product") if svc is not None else "") or ""
            version = (svc.get("version") if svc is not None else "") or ""
            banner = " ".join(x for x in (product, version) if x).strip()
            open_ports.append(portid)

            detail = f"{portid}/{name}" + (f" — {banner}" if banner else "")
            result.findings.append(Finding(
                module="nmap", target=target.display(),
                title=f"Open port {portid}/{name}" + (f" ({banner})" if banner else ""),
                severity=Severity.INFO, detail=detail,
                evidence={"port": portid, "service": name, "product": product, "version": version}))

            if name in _RISKY:
                sev, rec = _RISKY[name]
                result.findings.append(Finding(
                    module="nmap", target=target.display(),
                    title=f"Exposed service: {name} on {portid}", severity=sev,
                    detail=detail, recommendation=rec, evidence={"port": portid, "service": name}))

        if open_ports:
            result.findings.insert(0, Finding(
                module="nmap", target=target.display(),
                title=f"{len(open_ports)} open port(s)", severity=Severity.INFO,
                detail=", ".join(map(str, sorted(open_ports))),
                evidence={"open_ports": sorted(open_ports)}))
        report.results.append(result)

    report.scope_summary = {"source": str(path), "denied_targets": denied}
    import time
    report.finished = time.time()
    return report

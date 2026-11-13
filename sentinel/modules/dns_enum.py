"""DNS enumeration.

Includes a tiny dependency-free DNS resolver (UDP) so we can query A, AAAA, MX,
NS, TXT and CNAME records without pulling in dnspython. Also does reverse DNS
and a short common-subdomain sweep. All lookups stay within what the scope
authorizes (the hostname being audited and its own subdomains).
"""
from __future__ import annotations

import ipaddress
import socket
import struct
from pathlib import Path

from sentinel.core.models import Finding, Severity, Target
from sentinel.modules.base import AuditModule, ModuleContext, register

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
_FALLBACK_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
COMMON_SUBDOMAINS = ["www", "mail", "dev", "staging", "test", "api", "vpn",
                     "admin", "portal", "autodiscover", "ns1", "ns2"]


# --- minimal DNS client -----------------------------------------------------
def _system_resolver() -> str | None:
    try:
        text = Path("/etc/resolv.conf").read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
    except OSError:
        pass
    return None


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("idna" if any(ord(c) > 127 for c in label) else "ascii")
    return out + b"\x00"


def _build_query(name: str, qtype: int) -> bytes:
    tid = 0x1234
    flags = 0x0100  # recursion desired
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack(">HH", qtype, 1)  # class IN
    return header + question


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    end = offset
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if not jumped:
        end = offset
    return ".".join(labels), end


def _parse_rdata(data: bytes, rtype: int, rdlength: int, offset: int) -> str:
    if rtype == 1 and rdlength == 4:  # A
        return ".".join(str(b) for b in data[offset:offset + 4])
    if rtype == 28 and rdlength == 16:  # AAAA
        return str(ipaddress.IPv6Address(data[offset:offset + 16]))
    if rtype in (2, 5, 12):  # NS, CNAME, PTR
        name, _ = _read_name(data, offset)
        return name
    if rtype == 15:  # MX
        pref = struct.unpack(">H", data[offset:offset + 2])[0]
        name, _ = _read_name(data, offset + 2)
        return f"{pref} {name}"
    if rtype == 16:  # TXT
        txt, pos, end = [], offset, offset + rdlength
        while pos < end:
            ln = data[pos]; pos += 1
            txt.append(data[pos:pos + ln].decode("utf-8", "replace")); pos += ln
        return " ".join(txt)
    return data[offset:offset + rdlength].hex()


def dns_query(name: str, qtype: str, resolver: str, timeout: float) -> list[str]:
    """Perform a single DNS query; return list of answer rdata strings."""
    qt = QTYPES[qtype]
    packet = _build_query(name, qt)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (resolver, 53))
        data, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError):
        return []
    finally:
        sock.close()

    if len(data) < 12:
        return []
    _, _, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):  # skip question section
        _, offset = _read_name(data, offset)
        offset += 4
    answers = []
    for _ in range(an):
        _, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        answers.append(_parse_rdata(data, rtype, rdlength, offset))
        offset += rdlength
    return answers


@register
class DNSEnumModule(AuditModule):
    name = "dns"
    description = "Enumerate DNS records, reverse DNS, and common subdomains"

    def run(self, target: Target, ctx: ModuleContext) -> list[Finding]:
        host = target.hostname or target.spec
        findings: list[Finding] = []

        # If the target is a bare IP, do reverse DNS and stop.
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            try:
                name, _, _ = socket.gethostbyaddr(host)
                findings.append(self.finding(
                    target, "Reverse DNS (PTR) record",
                    severity=Severity.INFO, detail=name,
                    evidence={"ip": host, "ptr": name}))
            except (socket.herror, OSError):
                findings.append(self.finding(
                    target, "No reverse DNS record",
                    severity=Severity.INFO, evidence={"ip": host}))
            return findings

        resolver = _system_resolver() or _FALLBACK_RESOLVERS[0]

        for qtype in ("A", "AAAA", "NS", "MX", "TXT", "CNAME"):
            answers = dns_query(host, qtype, resolver, ctx.timeout)
            if answers:
                sev = Severity.INFO
                # SPF/DMARC visibility is useful context in TXT.
                findings.append(self.finding(
                    target, f"{qtype} record(s)",
                    severity=sev,
                    detail="; ".join(answers[:10]),
                    evidence={"type": qtype, "records": answers, "resolver": resolver}))

        # Common-subdomain sweep (only subdomains of the audited host).
        found_subs = []
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{host}"
            if dns_query(fqdn, "A", resolver, ctx.timeout):
                found_subs.append(fqdn)
        if found_subs:
            findings.append(self.finding(
                target, f"{len(found_subs)} common subdomain(s) resolve",
                severity=Severity.LOW,
                detail=", ".join(found_subs),
                recommendation="Review exposed subdomains; ensure none are forgotten/stale.",
                evidence={"subdomains": found_subs}))

        if not findings:
            findings.append(self.finding(
                target, "No DNS records resolved",
                severity=Severity.INFO,
                detail=f"Resolver {resolver} returned no answers (may be filtered in this environment)."))
        return findings

"""Tests for v0.3 features: exports, diff, nmap import, port cache, HTML filter."""
from __future__ import annotations

import json

from sentinel.core.models import AuditReport, Finding, ModuleResult, Severity, Target
from sentinel.core.report import to_csv, to_sarif, to_html, write_reports
from sentinel.core.diff import diff_reports
from sentinel.integrations.nmap_import import import_nmap
from sentinel.modules._netutil import PortCache


def _report() -> AuditReport:
    t = Target("host.test", "1.2.3.4")
    r = AuditReport(engagement="e", authorized_by="me", targets=[t])
    r.results = [ModuleResult("exposure", t.display(), findings=[
        Finding("exposure", t.display(), "Exposed .env file", severity=Severity.CRITICAL,
                recommendation="remove it"),
        Finding("http", t.display(), "Missing header: content-security-policy", severity=Severity.MEDIUM),
    ])]
    r.finished = r.started + 1
    return r


def test_sarif_is_valid_json_with_rules_and_results():
    s = json.loads(to_sarif(_report()))
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    assert run["tool"]["driver"]["name"] == "Sentinel Audit"
    assert len(run["results"]) == 2
    # critical maps to error level
    levels = {res["level"] for res in run["results"]}
    assert "error" in levels and "warning" in levels


def test_csv_has_header_and_rows():
    csv_text = to_csv(_report())
    lines = [l for l in csv_text.splitlines() if l.strip()]
    assert lines[0].startswith("severity,target,module,title")
    assert any("Exposed .env file" in l for l in lines[1:])


def test_html_filter_markup_present():
    html = to_html(_report())
    assert 'id="q"' in html and "sevbtn" in html
    assert 'data-sev="CRITICAL"' in html


def test_write_reports_all_formats(tmp_path):
    paths = write_reports(_report(), tmp_path, formats=("json", "md", "html", "sarif", "csv"))
    suffixes = {p.suffixes[-1] for p in paths}
    assert {".json", ".md", ".html", ".sarif", ".csv"} == suffixes
    for p in paths:
        assert p.exists() and p.stat().st_size > 0


def test_diff_detects_added_and_resolved(tmp_path):
    old = write_reports(_report(), tmp_path, basename="old", formats=("json",))[0]
    # New report: resolve the .env finding, keep header, add a new one
    t = Target("host.test", "1.2.3.4")
    r2 = AuditReport(engagement="e", authorized_by="me", targets=[t])
    r2.results = [ModuleResult("http", t.display(), findings=[
        Finding("http", t.display(), "Missing header: content-security-policy", severity=Severity.MEDIUM),
        Finding("tls", t.display(), "Deprecated TLSv1 accepted on port 443", severity=Severity.HIGH),
    ])]
    r2.finished = r2.started + 1
    new = write_reports(r2, tmp_path, basename="new", formats=("json",))[0]

    d = diff_reports(old, new)
    added = {f["title"] for f in d.added}
    resolved = {f["title"] for f in d.resolved}
    assert "Deprecated TLSv1 accepted on port 443" in added
    assert "Exposed .env file" in resolved
    assert d.summary()["unchanged"] == 1


def test_port_cache_probes_once(monkeypatch):
    import sentinel.modules._netutil as nu
    calls = {"n": 0}

    def fake_probe(ip, port, timeout):
        calls["n"] += 1
        return port == 80

    monkeypatch.setattr(nu, "tcp_open", fake_probe)
    cache = PortCache()
    assert cache.is_open("1.2.3.4", 80, 1.0) is True
    assert cache.is_open("1.2.3.4", 80, 1.0) is True   # cached
    assert cache.is_open("1.2.3.4", 81, 1.0) is False
    assert calls["n"] == 2  # 80 probed once, 81 probed once


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="box.test"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/></port>
      <port protocol="tcp" portid="23"><state state="open"/>
        <service name="telnet"/></port>
      <port protocol="tcp" portid="81"><state state="closed"/></port>
    </ports>
  </host>
</nmaprun>"""


def test_nmap_import(tmp_path):
    xml = tmp_path / "scan.xml"
    xml.write_text(NMAP_XML)
    report = import_nmap(xml)
    assert len(report.targets) == 1
    titles = [f.title for f in report.findings]
    assert any("2 open port(s)" in t for t in titles)
    assert any("telnet" in t.lower() and "Exposed" in t for t in titles)


def test_nmap_import_rejects_entities(tmp_path):
    xml = tmp_path / "evil.xml"
    xml.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><nmaprun></nmaprun>')
    try:
        import_nmap(xml)
        assert False, "should have refused DOCTYPE/ENTITY"
    except ValueError:
        pass

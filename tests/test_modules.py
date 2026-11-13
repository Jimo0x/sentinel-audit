"""Tests for module plumbing and report rendering (no network required)."""
from __future__ import annotations

from sentinel.core.models import AuditReport, Finding, ModuleResult, Severity, Target
from sentinel.core.report import to_html, to_json, to_markdown
from sentinel.modules import all_modules
from sentinel.modules.portscan import parse_ports


def test_all_builtin_modules_registered():
    names = set(all_modules())
    assert {"discovery", "portscan", "services", "tls", "http", "dns",
            "webcrawl", "exposure", "emailsec", "sshaudit"} <= names


def test_parse_ports_variants():
    assert parse_ports("22,80,443") == [22, 80, 443]
    assert parse_ports("1-3") == [1, 2, 3]
    assert parse_ports("full")[0] == 1 and parse_ports("full")[-1] == 65535
    assert 443 in parse_ports("common")


def test_parse_ports_dedup_and_bounds():
    assert parse_ports("80,80,80") == [80]
    assert parse_ports("0,70000,22") == [22]


def _sample_report() -> AuditReport:
    t = Target(spec="127.0.0.1", ip="127.0.0.1")
    f_hi = Finding(module="portscan", target=t.display(), title="Redis exposed",
                   severity=Severity.HIGH, recommendation="Lock it down")
    f_info = Finding(module="discovery", target=t.display(), title="Host is alive",
                     severity=Severity.INFO)
    r = AuditReport(engagement="t", authorized_by="me", targets=[t])
    r.results = [ModuleResult(module="portscan", target=t.display(), findings=[f_hi]),
                 ModuleResult(module="discovery", target=t.display(), findings=[f_info])]
    r.finished = r.started + 1
    return r


def test_severity_counts():
    rep = _sample_report()
    counts = rep.severity_counts()
    assert counts["HIGH"] == 1 and counts["INFO"] == 1


def test_renderers_produce_output():
    rep = _sample_report()
    js = to_json(rep)
    md = to_markdown(rep)
    html = to_html(rep)
    assert '"engagement": "t"' in js
    assert "Redis exposed" in md and "Host is alive" in md
    assert "<table>" in html and "Redis exposed" in html

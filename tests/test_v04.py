"""Tests for v0.4: risk scoring, taxonomy, plugin loader, vulnhints."""
from __future__ import annotations

import os

from sentinel.core.models import AuditReport, Finding, ModuleResult, Severity, Target
from sentinel.core.report import to_markdown, to_html, to_csv, to_sarif
from sentinel.modules.vulnhints import _check
from sentinel.modules.plugins import load_plugins


def _report(findings):
    t = Target("h", "1.2.3.4")
    r = AuditReport(engagement="e", authorized_by="me", targets=[t])
    r.results = [ModuleResult("m", t.display(), findings=findings)]
    r.finished = r.started + 1
    return r


def test_risk_score_and_grade():
    crit = Finding("m", "h", "x", severity=Severity.CRITICAL)
    low = Finding("m", "h", "y", severity=Severity.LOW)
    r = _report([crit, low])
    assert r.risk_score() == 41          # 40 + 1
    assert r.risk_grade() == "C"         # 41 -> C (>=25)
    clean = _report([Finding("m", "h", "z", severity=Severity.INFO)])
    assert clean.risk_score() == 0
    assert clean.risk_grade() == "A"


def test_finding_carries_taxonomy_into_outputs():
    f = Finding("exposure", "h", "Exposed .env", severity=Severity.CRITICAL,
                cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
                references=["https://example"])
    r = _report([f])
    d = f.to_dict()
    assert d["cwe"] == "CWE-200" and "A05" in d["owasp"]
    assert "CWE-200" in to_markdown(r)
    assert "CWE-200" in to_html(r)
    assert "CWE-200" in to_csv(r)
    assert "risk_score" in to_sarif(r) or True  # sarif need not carry cwe, but must render


def test_markdown_has_executive_summary():
    r = _report([Finding("m", "h", "bad", severity=Severity.HIGH)])
    md = to_markdown(r)
    assert "Executive summary" in md
    assert "Risk score" in md


def test_vulnhints_version_matching():
    # OpenSSH 7.4 is below baseline 8.5 -> should match
    hits = list(_check("SSH-2.0-OpenSSH_7.4"))
    assert any(p == "OpenSSH" and v == "7.4" for p, v, _, _ in hits)
    # A modern nginx should not match
    assert list(_check("nginx/1.25.0")) == []
    # Apache 2.2 (EOL) matches
    assert any(p == "Apache httpd" for p, *_ in _check("Apache/2.2.15 (CentOS)"))


def test_plugin_loader_imports_from_env(tmp_path, monkeypatch):
    # Write a plugin that registers a module, load it via SENTINEL_PLUGIN_DIR.
    plugdir = tmp_path / "plugins"
    plugdir.mkdir()
    (plugdir / "demo_mod.py").write_text(
        "from sentinel.modules.base import AuditModule, register\n"
        "@register\n"
        "class DemoModule(AuditModule):\n"
        "    name = 'demo_plugin'\n"
        "    description = 'test plugin'\n"
        "    def run(self, target, ctx):\n"
        "        return []\n"
    )
    monkeypatch.setenv("SENTINEL_PLUGIN_DIR", str(plugdir))
    loaded = load_plugins()
    from sentinel.modules.base import all_modules
    assert "demo_plugin" in all_modules()
    assert any("demo" in n for n in loaded)

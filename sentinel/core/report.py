"""Render an AuditReport to JSON, Markdown, HTML, SARIF, or CSV."""
from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from sentinel.core.models import AuditReport, Severity

from sentinel import __version__

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_COLOR = {
    "CRITICAL": "#7b1fa2",
    "HIGH": "#c62828",
    "MEDIUM": "#ef6c00",
    "LOW": "#f9a825",
    "INFO": "#1565c0",
}


def _ts(epoch: float | None) -> str:
    if not epoch:
        return "-"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


# ---------------------------------------------------------------------------
def to_json(report: AuditReport, *, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False)


# ---------------------------------------------------------------------------
def to_markdown(report: AuditReport) -> str:
    d = report.to_dict()
    counts = d["severity_counts"]
    lines: list[str] = []
    lines.append(f"# Security Audit Report — {report.engagement}\n")
    lines.append(f"- **Authorized by:** {report.authorized_by}")
    lines.append(f"- **Started:** {_ts(report.started)}")
    lines.append(f"- **Finished:** {_ts(report.finished)}")
    lines.append(f"- **Duration:** {d['duration_seconds']}s")
    lines.append(f"- **Targets audited:** {len(report.targets)}")
    lines.append("")

    lines.append("## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in _SEV_ORDER:
        lines.append(f"| {sev.label} | {counts[sev.name]} |")
    lines.append("")

    denied = report.scope_summary.get("denied_targets") or []
    if denied:
        lines.append("## Out-of-scope targets (not probed)\n")
        for msg in denied:
            lines.append(f"- {msg}")
        lines.append("")

    # Findings grouped by severity, highest first.
    findings = sorted(report.findings, key=lambda f: (-int(f.severity), f.target, f.module))
    lines.append("## Findings\n")
    if not findings:
        lines.append("_No findings recorded._\n")
    for f in findings:
        lines.append(f"### [{f.severity.label}] {f.title}")
        lines.append(f"- **Target:** {f.target}")
        lines.append(f"- **Module:** {f.module}")
        if f.detail:
            lines.append(f"- **Detail:** {f.detail}")
        if f.recommendation:
            lines.append(f"- **Recommendation:** {f.recommendation}")
        if f.evidence:
            ev = json.dumps(f.evidence, ensure_ascii=False)
            lines.append(f"- **Evidence:** `{ev}`")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
def to_html(report: AuditReport) -> str:
    d = report.to_dict()
    counts = d["severity_counts"]
    findings = sorted(report.findings, key=lambda f: (-int(f.severity), f.target, f.module))

    def esc(s: str) -> str:
        return html.escape(str(s))

    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLOR[s.name]}">'
        f'{s.label}: {counts[s.name]}</span>'
        for s in _SEV_ORDER
    )

    denied = report.scope_summary.get("denied_targets") or []
    denied_html = ""
    if denied:
        items = "".join(f"<li>{esc(m)}</li>" for m in denied)
        denied_html = f'<section><h2>Out of scope (not probed)</h2><ul class="denied">{items}</ul></section>'

    rows = []
    for f in findings:
        ev = esc(json.dumps(f.evidence, ensure_ascii=False)) if f.evidence else ""
        hay = esc(f"{f.target} {f.module} {f.title} {f.detail}").lower()
        rows.append(
            f'<tr class="finding" data-sev="{f.severity.name}" data-target="{esc(f.target)}" data-search="{hay}">'
            f'<td><span class="pill" style="background:{_SEV_COLOR[f.severity.name]}">{f.severity.label}</span></td>'
            f'<td>{esc(f.target)}</td>'
            f'<td>{esc(f.module)}</td>'
            f'<td><strong>{esc(f.title)}</strong>'
            + (f'<div class="detail">{esc(f.detail)}</div>' if f.detail else "")
            + (f'<div class="rec">↳ {esc(f.recommendation)}</div>' if f.recommendation else "")
            + (f'<div class="ev"><code>{ev}</code></div>' if ev else "")
            + f'</td></tr>'
        )
    rows_html = "\n".join(rows) or '<tr><td colspan="4">No findings recorded.</td></tr>'

    target_opts = "".join(f'<option value="{esc(t.display())}">{esc(t.display())}</option>'
                          for t in report.targets)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Audit Report — {esc(report.engagement)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; background: #0f1115; color: #e6e6e6; }}
  header {{ padding: 24px 32px; background: #161a22; border-bottom: 1px solid #272c38; }}
  h1 {{ margin: 0 0 6px; font-size: 20px; }}
  .meta {{ color: #9aa4b2; font-size: 13px; line-height: 1.6; }}
  main {{ padding: 24px 32px; max-width: 1100px; margin: 0 auto; }}
  .chips {{ margin: 12px 0 4px; display: flex; gap: 8px; flex-wrap: wrap; }}
  .chip {{ color: #fff; padding: 4px 10px; border-radius: 999px; font-size: 12px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #272c38;
           vertical-align: top; font-size: 14px; }}
  th {{ color: #9aa4b2; font-weight: 600; font-size: 12px; text-transform: uppercase; }}
  .pill {{ color: #fff; padding: 2px 8px; border-radius: 6px; font-size: 12px; white-space: nowrap; }}
  .detail {{ color: #c7cdd6; margin-top: 4px; }}
  .rec {{ color: #7fd1a0; margin-top: 4px; font-size: 13px; }}
  .ev code {{ color: #8ab4f8; font-size: 12px; word-break: break-all; }}
  .denied li {{ color: #c7cdd6; }}
  footer {{ padding: 16px 32px; color: #6b7280; font-size: 12px; }}
  .controls {{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin: 8px 0 4px; }}
  .controls input, .controls select {{ background:#0b0d12; color:#e6e6e6; border:1px solid #272c38;
      border-radius:6px; padding:7px 10px; font-size:13px; }}
  .controls input[type=search] {{ min-width: 220px; }}
  .sevbtn {{ cursor:pointer; user-select:none; padding:4px 10px; border-radius:999px; font-size:12px;
      border:1px solid #272c38; color:#e6e6e6; background:#0b0d12; }}
  .sevbtn.off {{ opacity:.35; }}
  .hidden {{ display:none; }}
  #count {{ color:#9aa4b2; font-size:12px; }}
</style></head>
<body>
<header>
  <h1>Security Audit Report — {esc(report.engagement)}</h1>
  <div class="meta">
    Authorized by {esc(report.authorized_by)}<br>
    {_ts(report.started)} → {_ts(report.finished)} · {d['duration_seconds']}s ·
    {len(report.targets)} target(s)
  </div>
  <div class="chips">{chips}</div>
</header>
<main>
  {denied_html}
  <section>
    <h2>Findings</h2>
    <div class="controls">
      <input type="search" id="q" placeholder="Search findings…">
      <select id="targetSel"><option value="">All targets</option>{target_opts}</select>
      <span id="sevbtns">
        <span class="sevbtn" data-sev="CRITICAL" style="border-color:{_SEV_COLOR['CRITICAL']}">Critical</span>
        <span class="sevbtn" data-sev="HIGH" style="border-color:{_SEV_COLOR['HIGH']}">High</span>
        <span class="sevbtn" data-sev="MEDIUM" style="border-color:{_SEV_COLOR['MEDIUM']}">Medium</span>
        <span class="sevbtn" data-sev="LOW" style="border-color:{_SEV_COLOR['LOW']}">Low</span>
        <span class="sevbtn" data-sev="INFO" style="border-color:{_SEV_COLOR['INFO']}">Info</span>
      </span>
      <span id="count"></span>
    </div>
    <table>
      <thead><tr><th>Severity</th><th>Target</th><th>Module</th><th>Finding</th></tr></thead>
      <tbody id="tbody">
      {rows_html}
      </tbody>
    </table>
  </section>
</main>
<footer>Generated by Sentinel Audit · authorized testing only.</footer>
<script>
(function() {{
  var off = {{}};  // severities toggled off
  var q = document.getElementById('q');
  var sel = document.getElementById('targetSel');
  var rows = Array.prototype.slice.call(document.querySelectorAll('tr.finding'));
  document.querySelectorAll('.sevbtn').forEach(function(b) {{
    b.addEventListener('click', function() {{
      var s = b.getAttribute('data-sev');
      off[s] = !off[s];
      b.classList.toggle('off', !!off[s]);
      apply();
    }});
  }});
  q.addEventListener('input', apply);
  sel.addEventListener('change', apply);
  function apply() {{
    var term = q.value.toLowerCase().trim();
    var tgt = sel.value;
    var shown = 0;
    rows.forEach(function(r) {{
      var ok = !off[r.dataset.sev]
        && (!tgt || r.dataset.target === tgt)
        && (!term || r.dataset.search.indexOf(term) !== -1);
      r.classList.toggle('hidden', !ok);
      if (ok) shown++;
    }});
    document.getElementById('count').textContent = shown + ' / ' + rows.length + ' shown';
  }}
  apply();
}})();
</script>
</body></html>"""


# ---------------------------------------------------------------------------
# SARIF 2.1.0 — for GitHub code scanning and other CI consumers.
_SARIF_LEVEL = {  # Severity -> SARIF level
    "CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
    "LOW": "note", "INFO": "none",
}


def to_sarif(report: AuditReport) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in report.findings:
        rule_id = f"{f.module}/{_slug(f.title)}"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity.name]},
            "properties": {"module": f.module, "security-severity": _security_severity(f.severity)},
        })
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[f.severity.name],
            "message": {"text": (f.detail or f.title) + (f"  Recommendation: {f.recommendation}" if f.recommendation else "")},
            "properties": {"target": f.target, "severity": f.severity.name, "evidence": f.evidence},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"sentinel://{f.target}/{f.module}"}
                }
            }],
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Sentinel Audit",
                "informationUri": "https://github.com/",
                "version": __version__,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _security_severity(sev: Severity) -> str:
    # CVSS-like 0-10 scale GitHub uses for sorting.
    return {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "3.0", "INFO": "0.0"}[sev.name]


def _slug(text: str) -> str:
    return "".join(c.lower() if c.isalnum() else "-" for c in text).strip("-")[:60] or "finding"


# ---------------------------------------------------------------------------
def to_csv(report: AuditReport) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "target", "module", "title", "detail", "recommendation", "evidence"])
    for f in sorted(report.findings, key=lambda x: (-int(x.severity), x.target, x.module)):
        w.writerow([f.severity.name, f.target, f.module, f.title, f.detail,
                    f.recommendation, json.dumps(f.evidence, ensure_ascii=False)])
    return buf.getvalue()


# ---------------------------------------------------------------------------
def write_reports(report: AuditReport, out_dir: str | Path, *, basename: str | None = None,
                  formats: tuple[str, ...] = ("json", "md", "html")) -> list[Path]:
    """Write report files and return the paths written."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    slug = (basename or report.engagement or "audit").lower()
    slug = "".join(c if c.isalnum() or c in "-_" else "-" for c in slug).strip("-") or "audit"
    base = out / f"{slug}-{stamp}"

    renderers = {
        "json": (".sentinel.json", to_json),
        "md": (".sentinel.md", to_markdown),
        "html": (".sentinel.html", to_html),
        "sarif": (".sentinel.sarif", to_sarif),
        "csv": (".sentinel.csv", to_csv),
    }
    written: list[Path] = []
    for fmt in formats:
        if fmt not in renderers:
            continue
        suffix, fn = renderers[fmt]
        p = base.with_suffix(suffix)
        p.write_text(fn(report), encoding="utf-8")
        written.append(p)
    return written

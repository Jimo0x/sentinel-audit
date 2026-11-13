"""Render an AuditReport to JSON, Markdown, or self-contained HTML."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from sentinel.core.models import AuditReport, Severity

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
        rows.append(
            f'<tr>'
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
    <table>
      <thead><tr><th>Severity</th><th>Target</th><th>Module</th><th>Finding</th></tr></thead>
      <tbody>
      {rows_html}
      </tbody>
    </table>
  </section>
</main>
<footer>Generated by Sentinel Audit · authorized testing only.</footer>
</body></html>"""


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

    written: list[Path] = []
    if "json" in formats:
        p = base.with_suffix(".sentinel.json"); p.write_text(to_json(report), encoding="utf-8"); written.append(p)
    if "md" in formats:
        p = base.with_suffix(".sentinel.md"); p.write_text(to_markdown(report), encoding="utf-8"); written.append(p)
    if "html" in formats:
        p = base.with_suffix(".sentinel.html"); p.write_text(to_html(report), encoding="utf-8"); written.append(p)
    return written

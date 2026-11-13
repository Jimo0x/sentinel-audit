"""Compare two Sentinel JSON reports to track remediation over time.

A finding is identified by (target, module, title). Comparing an older report
against a newer one tells you what was fixed, what is new, and what persists —
the core of tracking remediation between assessments.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _key(f: dict) -> tuple[str, str, str]:
    return (f.get("target", ""), f.get("module", ""), f.get("title", ""))


def _load_findings(path: str | Path) -> dict[tuple[str, str, str], dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out: dict[tuple[str, str, str], dict] = {}
    for result in data.get("results", []):
        for f in result.get("findings", []):
            out[_key(f)] = f
    return out


@dataclass
class DiffReport:
    old_path: str
    new_path: str
    added: list[dict] = field(default_factory=list)      # new findings
    resolved: list[dict] = field(default_factory=list)   # gone in new
    unchanged: list[dict] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        return {"added": len(self.added), "resolved": len(self.resolved),
                "unchanged": len(self.unchanged)}

    def to_dict(self) -> dict[str, Any]:
        return {"old": self.old_path, "new": self.new_path,
                "summary": self.summary(),
                "added": self.added, "resolved": self.resolved,
                "unchanged": self.unchanged}


def diff_reports(old_path: str | Path, new_path: str | Path) -> DiffReport:
    old = _load_findings(old_path)
    new = _load_findings(new_path)
    report = DiffReport(str(old_path), str(new_path))
    for k, f in new.items():
        (report.unchanged if k in old else report.added).append(f)
    for k, f in old.items():
        if k not in new:
            report.resolved.append(f)
    # Sort each bucket by severity desc for readable output.
    for bucket in (report.added, report.resolved, report.unchanged):
        bucket.sort(key=lambda x: -int(x.get("severity_level", 0)))
    return report


def render_diff_text(d: DiffReport) -> str:
    lines = [f"Diff: {d.old_path}  ->  {d.new_path}", ""]
    s = d.summary()
    lines.append(f"  + {s['added']} new   - {s['resolved']} resolved   = {s['unchanged']} unchanged")
    lines.append("")
    if d.resolved:
        lines.append("RESOLVED (fixed since the old report):")
        for f in d.resolved:
            lines.append(f"  - [{f.get('severity')}] {f.get('target')} / {f.get('module')} — {f.get('title')}")
        lines.append("")
    if d.added:
        lines.append("NEW (appeared in the new report):")
        for f in d.added:
            lines.append(f"  + [{f.get('severity')}] {f.get('target')} / {f.get('module')} — {f.get('title')}")
        lines.append("")
    if not d.added and not d.resolved:
        lines.append("No change in findings between the two reports.")
    return "\n".join(lines)

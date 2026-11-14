"""Core data models shared across the framework.

Everything a module discovers is expressed as a `Finding`. Findings carry a
`Severity`, which lets the reporting layer sort and summarize automatically.
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field, asdict
from typing import Any


class Severity(enum.IntEnum):
    """Ordered severity levels. Higher value = more urgent."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"unknown severity: {value!r}") from exc


@dataclass
class Target:
    """A single resolved host under audit.

    `spec` is what the user/scope asked for (a hostname or IP); `ip` is the
    resolved address actually probed. Keeping both makes reports unambiguous.
    """

    spec: str
    ip: str | None = None
    hostname: str | None = None

    def display(self) -> str:
        if self.ip and self.ip != self.spec:
            return f"{self.spec} ({self.ip})"
        return self.spec


@dataclass
class Finding:
    """A single observation produced by a module."""

    module: str
    target: str
    title: str
    severity: Severity = Severity.INFO
    detail: str = ""
    # Free-form structured evidence (open port numbers, header values, etc.)
    evidence: dict[str, Any] = field(default_factory=dict)
    # Optional remediation guidance for report readers.
    recommendation: str = ""
    # Optional classification for professional reporting.
    cwe: str | None = None             # e.g. "CWE-16"
    owasp: str | None = None           # e.g. "A05:2021 Security Misconfiguration"
    references: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["severity_level"] = int(self.severity)
        return d


@dataclass
class ModuleResult:
    """Outcome of running one module against one target."""

    module: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    started: float = field(default_factory=time.time)
    finished: float | None = None

    @property
    def duration(self) -> float:
        return (self.finished or time.time()) - self.started

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "error": self.error,
            "duration_seconds": round(self.duration, 3),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class AuditReport:
    """The full result of an engagement run."""

    engagement: str
    authorized_by: str
    started: float = field(default_factory=time.time)
    finished: float | None = None
    targets: list[Target] = field(default_factory=list)
    results: list[ModuleResult] = field(default_factory=list)
    scope_summary: dict[str, Any] = field(default_factory=dict)

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for r in self.results:
            out.extend(r.findings)
        return out

    def severity_counts(self) -> dict[str, int]:
        counts = {s.name: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    # Weighted risk score (0-100) for an at-a-glance posture read.
    _RISK_WEIGHTS = {"CRITICAL": 40, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0}

    def risk_score(self) -> int:
        counts = self.severity_counts()
        raw = sum(self._RISK_WEIGHTS[s] * n for s, n in counts.items())
        return min(100, raw)

    def risk_grade(self) -> str:
        s = self.risk_score()
        if s >= 70: return "F"
        if s >= 45: return "D"
        if s >= 25: return "C"
        if s >= 10: return "B"
        return "A"

    def top_findings(self, n: int = 5) -> list[Finding]:
        return sorted(self.findings, key=lambda f: -int(f.severity))[:n]

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement": self.engagement,
            "authorized_by": self.authorized_by,
            "started": self.started,
            "finished": self.finished,
            "duration_seconds": round((self.finished or time.time()) - self.started, 3),
            "scope_summary": self.scope_summary,
            "targets": [asdict(t) for t in self.targets],
            "severity_counts": self.severity_counts(),
            "risk_score": self.risk_score(),
            "risk_grade": self.risk_grade(),
            "results": [r.to_dict() for r in self.results],
        }

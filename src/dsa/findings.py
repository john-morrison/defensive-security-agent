from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_ORDER: dict[Severity, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    path: Path
    line: int
    evidence: str
    rationale: str
    recommendation: str
    source: str = "builtin"
    tags: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ScanResult:
    target: Path
    scanned_files: int
    skipped_files: int
    findings: tuple[Finding, ...]
    tool_notes: tuple[str, ...] = field(default_factory=tuple)


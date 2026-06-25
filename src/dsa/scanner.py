from __future__ import annotations

from pathlib import Path

from .external_scanners import run_external_scanners
from .findings import SEVERITY_ORDER, Finding, ScanResult
from .rules import BUILTIN_RULES

SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".cxx",
    ".go",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".sql",
    ".ts",
    ".tsx",
}

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
}


def scan_target(
    target: Path,
    include_semgrep: bool,
    max_file_kb: int,
    external_scanners: tuple[str, ...] = (),
) -> ScanResult:
    if not target.exists():
        raise FileNotFoundError(f"target does not exist: {target}")

    files = list(_iter_source_files(target, max_file_kb=max_file_kb))
    skipped = _count_skipped_source_files(target, max_file_kb=max_file_kb)
    findings: list[Finding] = []
    notes: list[str] = []

    for path in files:
        findings.extend(_scan_file(path))

    requested_scanners = list(external_scanners)
    if include_semgrep and "semgrep" not in requested_scanners:
        requested_scanners.append("semgrep")
    if requested_scanners:
        external_findings, external_notes = run_external_scanners(
            target,
            tuple(dict.fromkeys(requested_scanners)),
        )
        findings.extend(external_findings)
        notes.extend(external_notes)

    ordered = tuple(
        sorted(
            findings,
            key=lambda item: (
                SEVERITY_ORDER[item.severity],
                str(item.path),
                item.line,
                item.rule_id,
            ),
        )
    )
    return ScanResult(
        target=target,
        scanned_files=len(files),
        skipped_files=skipped,
        findings=ordered,
        tool_notes=tuple(notes),
    )


def _iter_source_files(target: Path, max_file_kb: int) -> list[Path]:
    if target.is_file():
        return [target] if _is_source_file(target, max_file_kb) else []

    files: list[Path] = []
    for path in target.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file() and _is_source_file(path, max_file_kb):
            files.append(path)
    return files


def _count_skipped_source_files(target: Path, max_file_kb: int) -> int:
    candidates = [target] if target.is_file() else list(target.rglob("*"))
    count = 0
    for path in candidates:
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS:
            try:
                if path.stat().st_size > max_file_kb * 1024:
                    count += 1
            except OSError:
                count += 1
    return count


def _is_source_file(path: Path, max_file_kb: int) -> bool:
    if path.suffix.lower() not in SOURCE_EXTENSIONS:
        return False
    try:
        return path.stat().st_size <= max_file_kb * 1024
    except OSError:
        return False


def _scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        for rule in BUILTIN_RULES:
            if rule.extensions and path.suffix.lower() not in rule.extensions:
                continue
            if rule.pattern.search(stripped):
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        path=path,
                        line=line_number,
                        evidence=stripped[:240],
                        rationale=rule.rationale,
                        recommendation=rule.recommendation,
                        tags=rule.tags,
                    )
                )
    return findings

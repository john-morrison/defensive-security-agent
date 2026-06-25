from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .findings import Finding, Severity

ScannerParser = Callable[[Path, dict[str, Any]], list[Finding]]


@dataclass(frozen=True)
class ExternalScanner:
    name: str
    executable: str
    command: tuple[str, ...]
    parser: ScannerParser
    timeout_seconds: int = 600


SUPPORTED_SCANNERS: dict[str, ExternalScanner] = {
    "semgrep": ExternalScanner(
        name="semgrep",
        executable="semgrep",
        command=("semgrep", "scan", "--config", "auto", "--json", "--quiet", "{target}"),
        parser=lambda target, payload: parse_semgrep(target, payload),
    ),
    "bandit": ExternalScanner(
        name="bandit",
        executable="bandit",
        command=("bandit", "-r", "{target}", "-f", "json", "-q"),
        parser=lambda target, payload: parse_bandit(target, payload),
    ),
    "pip-audit": ExternalScanner(
        name="pip-audit",
        executable="pip-audit",
        command=("pip-audit", "--path", "{target}", "--format", "json"),
        parser=lambda target, payload: parse_pip_audit(target, payload),
    ),
    "npm-audit": ExternalScanner(
        name="npm-audit",
        executable="npm",
        command=("npm", "audit", "--json", "--audit-level", "low", "--prefix", "{target}"),
        parser=lambda target, payload: parse_npm_audit(target, payload),
    ),
    "gitleaks": ExternalScanner(
        name="gitleaks",
        executable="gitleaks",
        command=("gitleaks", "detect", "--source", "{target}", "--report-format", "json", "--no-banner"),
        parser=lambda target, payload: parse_gitleaks(target, payload),
    ),
    "detect-secrets": ExternalScanner(
        name="detect-secrets",
        executable="detect-secrets",
        command=("detect-secrets", "scan", "{target}"),
        parser=lambda target, payload: parse_detect_secrets(target, payload),
    ),
    "checkov": ExternalScanner(
        name="checkov",
        executable="checkov",
        command=("checkov", "-d", "{target}", "-o", "json", "--quiet"),
        parser=lambda target, payload: parse_checkov(target, payload),
    ),
    "osv-scanner": ExternalScanner(
        name="osv-scanner",
        executable="osv-scanner",
        command=("osv-scanner", "--format", "json", "-r", "{target}"),
        parser=lambda target, payload: parse_osv_scanner(target, payload),
    ),
    "grype": ExternalScanner(
        name="grype",
        executable="grype",
        command=("grype", "dir:{target}", "-o", "json", "--quiet"),
        parser=lambda target, payload: parse_grype(target, payload),
    ),
    "gosec": ExternalScanner(
        name="gosec",
        executable="gosec",
        command=("gosec", "-fmt", "json", "-quiet", "./..."),
        parser=lambda target, payload: parse_gosec(target, payload),
    ),
}


def run_external_scanners(
    target: Path,
    scanner_names: tuple[str, ...],
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    notes: list[str] = []
    for name in scanner_names:
        scanner = SUPPORTED_SCANNERS.get(name)
        if scanner is None:
            notes.append(f"Unsupported external scanner requested: {name}")
            continue
        scanner_findings, scanner_notes = _run_scanner(target, scanner)
        findings.extend(scanner_findings)
        notes.extend(scanner_notes)
    return findings, notes


def _run_scanner(target: Path, scanner: ExternalScanner) -> tuple[list[Finding], list[str]]:
    if shutil.which(scanner.executable) is None:
        return [], [f"{scanner.name} was requested but `{scanner.executable}` was not found."]

    command = [part.replace("{target}", str(target)) for part in scanner.command]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=scanner.timeout_seconds,
            cwd=str(target) if scanner.name == "gosec" and target.is_dir() else None,
        )
    except subprocess.TimeoutExpired:
        return [], [f"{scanner.name} timed out after {scanner.timeout_seconds} seconds."]

    notes: list[str] = []
    if completed.stderr.strip():
        notes.append(f"{scanner.name} stderr: {completed.stderr.strip()[:500]}")

    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return [], notes + [f"{scanner.name} returned non-JSON output."]

    try:
        return scanner.parser(target, payload), notes
    except Exception as exc:  # defensive parser isolation
        return [], notes + [f"{scanner.name} parser failed: {exc}"]


def parse_semgrep(target: Path, payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        start = result.get("start", {})
        metadata = extra.get("metadata", {})
        findings.append(
            Finding(
                rule_id=str(result.get("check_id", "semgrep.unknown")),
                title=str(extra.get("message", "Semgrep finding")),
                severity=_normalize_semgrep_severity(extra.get("severity")),
                path=Path(str(result.get("path", target))),
                line=_int(start.get("line"), 1),
                evidence=str(extra.get("lines", "")).strip()[:240],
                rationale="Semgrep reported this issue from its selected ruleset.",
                recommendation=str(metadata.get("fix", "Review and remediate this finding.")),
                source="semgrep",
                tags=("semgrep",),
            )
        )
    return findings


def parse_bandit(target: Path, payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for result in payload.get("results", []):
        findings.append(
            Finding(
                rule_id=f"bandit.{result.get('test_id', 'unknown')}",
                title=str(result.get("test_name") or result.get("issue_text") or "Bandit finding"),
                severity=_normalize_bandit_severity(result.get("issue_severity")),
                path=Path(str(result.get("filename", target))),
                line=_int(result.get("line_number"), 1),
                evidence=str(result.get("code", "")).strip()[:240],
                rationale=str(result.get("issue_text", "Bandit reported this Python security issue.")),
                recommendation="Review the Bandit finding and apply the recommended secure coding pattern.",
                source="bandit",
                tags=("bandit", "python"),
            )
        )
    return findings


def parse_pip_audit(target: Path, payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for dependency in payload.get("dependencies", []):
        name = str(dependency.get("name", "unknown"))
        version = str(dependency.get("version", "unknown"))
        for vuln in dependency.get("vulns", []):
            vuln_id = str(vuln.get("id", "unknown"))
            findings.append(
                Finding(
                    rule_id=f"pip-audit.{vuln_id}",
                    title=f"Python dependency vulnerability: {name} {version}",
                    severity="high",
                    path=target,
                    line=1,
                    evidence=str(vuln.get("description", ""))[:240],
                    rationale=f"pip-audit reported vulnerability {vuln_id} in {name}.",
                    recommendation=_fix_versions(vuln) or "Upgrade the affected dependency to a fixed version.",
                    source="pip-audit",
                    tags=("dependency", "python", "cve"),
                )
            )
    return findings


def parse_npm_audit(target: Path, payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    vulnerabilities = payload.get("vulnerabilities", {})
    for name, vuln in vulnerabilities.items():
        findings.append(
            Finding(
                rule_id=f"npm-audit.{name}",
                title=f"npm dependency vulnerability: {name}",
                severity=_normalize_npm_severity(vuln.get("severity")),
                path=target / "package-lock.json",
                line=1,
                evidence=str(vuln.get("title") or vuln.get("name") or name)[:240],
                rationale=str(vuln.get("overview") or "npm audit reported a dependency vulnerability."),
                recommendation=str(vuln.get("recommendation") or vuln.get("fixAvailable") or "Update the dependency or apply npm audit fix after review."),
                source="npm-audit",
                tags=("dependency", "javascript", "npm"),
            )
        )
    return findings


def parse_gitleaks(target: Path, payload: dict[str, Any]) -> list[Finding]:
    results = payload if isinstance(payload, list) else payload.get("findings", [])
    findings: list[Finding] = []
    for result in results:
        path = Path(str(result.get("File") or result.get("file") or target))
        findings.append(
            Finding(
                rule_id=f"gitleaks.{result.get('RuleID') or result.get('rule_id') or 'secret'}",
                title=str(result.get("Description") or result.get("description") or "Potential secret"),
                severity="high",
                path=path,
                line=_int(result.get("StartLine") or result.get("start_line"), 1),
                evidence=str(result.get("Match") or result.get("match") or result.get("Secret") or "")[:240],
                rationale="Gitleaks reported a potential secret in source control.",
                recommendation="Remove the secret, rotate it if real, and move credentials to an approved secret manager.",
                source="gitleaks",
                tags=("secret", "gitleaks"),
            )
        )
    return findings


def parse_detect_secrets(target: Path, payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for filename, entries in payload.get("results", {}).items():
        for entry in entries:
            findings.append(
                Finding(
                    rule_id=f"detect-secrets.{entry.get('type', 'secret')}",
                    title=f"Potential secret: {entry.get('type', 'unknown')}",
                    severity="high",
                    path=Path(filename),
                    line=_int(entry.get("line_number"), 1),
                    evidence=str(entry.get("hashed_secret", "secret candidate"))[:240],
                    rationale="detect-secrets reported a potential secret.",
                    recommendation="Review, remove, and rotate the secret if real.",
                    source="detect-secrets",
                    tags=("secret", "detect-secrets"),
                )
            )
    return findings


def parse_checkov(target: Path, payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    sections = payload if isinstance(payload, list) else [payload]
    for section in sections:
        for result in section.get("results", {}).get("failed_checks", []):
            findings.append(
                Finding(
                    rule_id=f"checkov.{result.get('check_id', 'unknown')}",
                    title=str(result.get("check_name", "Checkov finding")),
                    severity="medium",
                    path=Path(str(result.get("file_path", target))),
                    line=_first_line(result.get("file_line_range")),
                    evidence=str(result.get("resource", ""))[:240],
                    rationale="Checkov reported an infrastructure-as-code security issue.",
                    recommendation=str(result.get("guideline") or "Review the Checkov check and harden the configuration."),
                    source="checkov",
                    tags=("iac", "checkov"),
                )
            )
    return findings


def parse_osv_scanner(target: Path, payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for result in payload.get("results", []):
        source = result.get("source", {})
        path = Path(str(source.get("path", target)))
        for package in result.get("packages", []):
            package_info = package.get("package", {})
            package_name = str(package_info.get("name", "unknown"))
            for vuln in package.get("vulnerabilities", []):
                findings.append(
                    Finding(
                        rule_id=f"osv-scanner.{vuln.get('id', 'unknown')}",
                        title=f"OSV dependency vulnerability: {package_name}",
                        severity="high",
                        path=path,
                        line=1,
                        evidence=str(vuln.get("summary", ""))[:240],
                        rationale="OSV-Scanner reported a dependency vulnerability.",
                        recommendation="Upgrade or replace the affected dependency according to the vulnerability advisory.",
                        source="osv-scanner",
                        tags=("dependency", "osv"),
                    )
                )
    return findings


def parse_grype(target: Path, payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for match in payload.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        locations = artifact.get("locations") or []
        path = Path(str((locations[0].get("path") if locations else "") or target))
        findings.append(
            Finding(
                rule_id=f"grype.{vuln.get('id', 'unknown')}",
                title=f"Dependency/container vulnerability: {artifact.get('name', 'unknown')}",
                severity=_normalize_grype_severity(vuln.get("severity")),
                path=path,
                line=1,
                evidence=str(vuln.get("description") or vuln.get("id") or "")[:240],
                rationale="Grype reported a dependency or container vulnerability.",
                recommendation=str(vuln.get("fix", {}).get("versions") or "Upgrade to a non-vulnerable version when available."),
                source="grype",
                tags=("dependency", "container", "grype"),
            )
        )
    return findings


def parse_gosec(target: Path, payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for issue in payload.get("Issues", []) or payload.get("issues", []):
        findings.append(
            Finding(
                rule_id=f"gosec.{issue.get('rule_id') or issue.get('rule') or 'unknown'}",
                title=str(issue.get("details", "Gosec finding")),
                severity=_normalize_gosec_severity(issue.get("severity")),
                path=Path(str(issue.get("file", target))),
                line=_int(issue.get("line"), 1),
                evidence=str(issue.get("code", ""))[:240],
                rationale="Gosec reported a Go security issue.",
                recommendation="Review and remediate the Gosec finding.",
                source="gosec",
                tags=("go", "gosec"),
            )
        )
    return findings


def available_scanners() -> tuple[str, ...]:
    return tuple(name for name, scanner in SUPPORTED_SCANNERS.items() if shutil.which(scanner.executable))


def _normalize_semgrep_severity(value: object) -> Severity:
    text = str(value or "").lower()
    if text in {"error", "critical"}:
        return "critical"
    if text == "warning":
        return "high"
    if text == "info":
        return "low"
    return "medium"


def _normalize_bandit_severity(value: object) -> Severity:
    text = str(value or "").lower()
    if text == "high":
        return "high"
    if text == "medium":
        return "medium"
    if text == "low":
        return "low"
    return "medium"


def _normalize_npm_severity(value: object) -> Severity:
    text = str(value or "").lower()
    if text == "critical":
        return "critical"
    if text == "high":
        return "high"
    if text == "moderate":
        return "medium"
    if text == "low":
        return "low"
    return "medium"


def _normalize_grype_severity(value: object) -> Severity:
    text = str(value or "").lower()
    if text == "critical":
        return "critical"
    if text == "high":
        return "high"
    if text == "medium":
        return "medium"
    if text in {"low", "negligible"}:
        return "low"
    return "medium"


def _normalize_gosec_severity(value: object) -> Severity:
    text = str(value or "").lower()
    if text == "high":
        return "high"
    if text == "medium":
        return "medium"
    if text == "low":
        return "low"
    return "medium"


def _int(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _first_line(value: object) -> int:
    if isinstance(value, list) and value:
        return _int(value[0], 1)
    return 1


def _fix_versions(vuln: dict[str, Any]) -> str:
    versions = vuln.get("fix_versions") or vuln.get("fixed_versions")
    if isinstance(versions, list) and versions:
        return f"Upgrade to one of the fixed versions: {', '.join(str(version) for version in versions)}."
    return ""

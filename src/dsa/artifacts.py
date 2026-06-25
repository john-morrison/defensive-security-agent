from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from .findings import Finding, ScanResult
from .java_rest_verifier import VerificationResult, VerificationTrace

SCHEMA_VERSION = 1
SCAN_ARTIFACT_TYPE = "dsa.scan.v1"
JAVA_REST_VERIFICATION_ARTIFACT_TYPE = "dsa.verification.java-rest.v1"


def scan_result_to_artifact(result: ScanResult) -> dict[str, Any]:
    return {
        "artifact_type": SCAN_ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "target": str(result.target),
        "scanned_files": result.scanned_files,
        "skipped_files": result.skipped_files,
        "tool_notes": list(result.tool_notes),
        "findings": [_finding_to_dict(finding) for finding in result.findings],
    }


def verification_result_to_artifact(result: VerificationResult) -> dict[str, Any]:
    return {
        "artifact_type": JAVA_REST_VERIFICATION_ARTIFACT_TYPE,
        "schema_version": SCHEMA_VERSION,
        "target": str(result.target),
        "scanned_files": result.scanned_files,
        "notes": list(result.notes),
        "traces": [_trace_to_dict(trace) for trace in result.traces],
    }


def write_artifact(path: Path, artifact: dict[str, Any]) -> None:
    path.write_text(json.dumps(_json_safe(artifact), indent=2) + "\n", encoding="utf-8")


def load_artifact(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"artifact must be a JSON object: {path}")
    artifact_type = payload.get("artifact_type")
    if artifact_type not in {SCAN_ARTIFACT_TYPE, JAVA_REST_VERIFICATION_ARTIFACT_TYPE}:
        raise ValueError(f"unsupported artifact type: {artifact_type!r}")
    return payload


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "id": _stable_id(finding.rule_id, finding.path, finding.line),
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "path": str(finding.path),
        "line": finding.line,
        "evidence": finding.evidence,
        "rationale": finding.rationale,
        "recommendation": finding.recommendation,
        "source": finding.source,
        "tags": list(finding.tags),
    }


def _trace_to_dict(trace: VerificationTrace) -> dict[str, Any]:
    return {
        "id": _stable_id(trace.bug_class, trace.path, trace.sink_line),
        "status": trace.status,
        "bug_class": trace.bug_class,
        "path": str(trace.path),
        "method_name": trace.method_name,
        "method_line": trace.method_line,
        "source_line": trace.source_line,
        "source_evidence": trace.source_evidence,
        "sink_line": trace.sink_line,
        "sink_evidence": trace.sink_evidence,
        "tainted_symbols": list(trace.tainted_symbols),
        "guard_evidence": list(trace.guard_evidence),
        "rationale": trace.rationale,
        "recommendation": trace.recommendation,
    }


def _stable_id(kind: str, path: Path, line: int) -> str:
    return f"{kind}:{path}:{line}"


def _json_safe(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return _json_safe(asdict(value))
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return value

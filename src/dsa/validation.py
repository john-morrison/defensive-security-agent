from __future__ import annotations

import json
import shlex
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlencode, urlparse
import urllib.error
import urllib.request

from .artifacts import (
    JAVA_REST_VERIFICATION_ARTIFACT_TYPE,
    SCAN_ARTIFACT_TYPE,
    load_artifact,
)
from .siebel_sam_rest_pocs import PocCase, build_cases, curl_command, execute_case

ValidationProfile = Literal["generic", "siebel-sam-rest", "http-probe"]
ExecutionStatus = Literal[
    "planned",
    "sent",
    "manual-verification-required",
    "network-error",
    "blocked",
]

PAYLOAD_SETS: dict[str, tuple[str, ...]] = {
    "sqli-basic": (
        "'",
        "\"",
        "' OR '1'='1",
        "' AND '1'='2",
        "1 OR 1=1",
        "1 AND 1=2",
    ),
    "xss-reflection": (
        "<script>DSA_PROBE</script>",
        "\"><svg onload=alert('DSA_PROBE')>",
        "'><img src=x onerror=alert('DSA_PROBE')>",
    ),
    "path-traversal-canary": (
        "../DSA_CANARY.txt",
        "..%2FDSA_CANARY.txt",
        "....//DSA_CANARY.txt",
    ),
    "command-injection-marker": (
        "dsa_probe",
        "dsa_probe; echo DSA_PROBE",
        "dsa_probe && echo DSA_PROBE",
        "dsa_probe | echo DSA_PROBE",
    ),
    "xml-parser-marker": (
        "<dsa>probe</dsa>",
        "<!DOCTYPE dsa [<!ENTITY marker \"DSA_PROBE\">]><dsa>&marker;</dsa>",
    ),
}


@dataclass(frozen=True)
class SourceReference:
    artifact_type: str
    ref_id: str
    title: str
    category: str
    severity: str
    path: str
    line: int
    evidence: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class ValidationStep:
    order: int
    action: str
    expected_result: str
    command: str = ""


@dataclass(frozen=True)
class ExecutionEvidence:
    status: ExecutionStatus
    http_status: int | None = None
    response_preview: str = ""
    note: str = ""


@dataclass(frozen=True)
class ValidationCase:
    case_id: str
    title: str
    category: str
    severity: str
    source_refs: tuple[SourceReference, ...]
    steps: tuple[ValidationStep, ...]
    safe_mode: str
    request_command: str = ""
    marker_file: str = ""
    manual_verification: str = ""
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    execution: ExecutionEvidence = field(
        default_factory=lambda: ExecutionEvidence(status="planned")
    )


@dataclass(frozen=True)
class DeploymentValidationResult:
    artifact_path: Path
    artifact_type: str
    base_url: str
    profile: ValidationProfile
    executed: bool
    aggressive_sandbox: bool
    cases: tuple[ValidationCase, ...]
    notes: tuple[str, ...] = ()


def validate_artifact(
    artifact_path: Path,
    base_url: str,
    profile: ValidationProfile,
    execute: bool = False,
    allow_hosts: tuple[str, ...] = (),
    timeout: int = 20,
    probe_spec_path: Path | None = None,
    aggressive_sandbox: bool = False,
    max_mutations_per_case: int = 25,
) -> DeploymentValidationResult:
    artifact = load_artifact(artifact_path)
    _validate_base_url(base_url)
    if execute:
        _require_host_allowlisted(base_url, allow_hosts)

    source_refs = _source_refs(artifact)
    notes: list[str] = []

    if profile == "siebel-sam-rest":
        cases = _siebel_sam_rest_cases(source_refs, base_url)
        if not cases:
            notes.append(
                "No Siebel SAM REST validation case mapped to the supplied artifact. "
                "Use the generic profile or add a repository-specific validator."
            )
    elif profile == "http-probe":
        if probe_spec_path is None:
            raise ValueError("--probe-spec is required with --profile http-probe")
        cases, probe_notes = _http_probe_cases(
            source_refs,
            base_url,
            probe_spec_path,
            aggressive_sandbox=aggressive_sandbox,
            max_mutations_per_case=max_mutations_per_case,
        )
        notes.extend(probe_notes)
    else:
        cases = _generic_cases(source_refs)

    if execute:
        cases = tuple(_execute_case(case, base_url, timeout) for case in cases)

    return DeploymentValidationResult(
        artifact_path=artifact_path,
        artifact_type=str(artifact.get("artifact_type")),
        base_url=base_url,
        profile=profile,
        executed=execute,
        aggressive_sandbox=aggressive_sandbox,
        cases=cases,
        notes=tuple(notes),
    )


def validation_result_to_dict(result: DeploymentValidationResult) -> dict[str, Any]:
    return {
        "artifact_path": str(result.artifact_path),
        "artifact_type": result.artifact_type,
        "base_url": result.base_url,
        "profile": result.profile,
        "executed": result.executed,
        "aggressive_sandbox": result.aggressive_sandbox,
        "notes": list(result.notes),
        "cases": [_case_to_dict(case) for case in result.cases],
    }


def write_validation_json(path: Path, result: DeploymentValidationResult) -> None:
    path.write_text(json.dumps(validation_result_to_dict(result), indent=2) + "\n", encoding="utf-8")


def _validate_base_url(base_url: str) -> None:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("--base-url must be an http(s) URL with a host")


def _require_host_allowlisted(base_url: str, allow_hosts: tuple[str, ...]) -> None:
    host = (urlparse(base_url).hostname or "").lower()
    allowed = {item.lower() for item in allow_hosts}
    if host not in allowed:
        raise ValueError(
            f"execution blocked: target host {host!r} is not in --allow-host"
        )


def _source_refs(artifact: dict[str, Any]) -> tuple[SourceReference, ...]:
    artifact_type = str(artifact.get("artifact_type"))
    if artifact_type == SCAN_ARTIFACT_TYPE:
        return tuple(_finding_ref(artifact_type, finding) for finding in artifact.get("findings", []))
    if artifact_type == JAVA_REST_VERIFICATION_ARTIFACT_TYPE:
        return tuple(_trace_ref(artifact_type, trace) for trace in artifact.get("traces", []))
    return ()


def _finding_ref(artifact_type: str, finding: dict[str, Any]) -> SourceReference:
    return SourceReference(
        artifact_type=artifact_type,
        ref_id=str(finding.get("id", "")),
        title=str(finding.get("title", "Finding")),
        category=str(finding.get("rule_id", "unknown")),
        severity=str(finding.get("severity", "medium")),
        path=str(finding.get("path", "")),
        line=int(finding.get("line", 0) or 0),
        evidence=str(finding.get("evidence", "")),
        tags=tuple(str(tag) for tag in finding.get("tags", [])),
    )


def _trace_ref(artifact_type: str, trace: dict[str, Any]) -> SourceReference:
    return SourceReference(
        artifact_type=artifact_type,
        ref_id=str(trace.get("id", "")),
        title=f"{trace.get('bug_class', 'source-to-sink')} trace in {trace.get('method_name', 'method')}",
        category=str(trace.get("bug_class", "unknown")),
        severity="high" if trace.get("status") == "verified" else "medium",
        path=str(trace.get("path", "")),
        line=int(trace.get("sink_line", 0) or 0),
        evidence=str(trace.get("sink_evidence", "")),
        tags=(str(trace.get("bug_class", "unknown")),),
    )


def _siebel_sam_rest_cases(
    source_refs: tuple[SourceReference, ...],
    base_url: str,
) -> tuple[ValidationCase, ...]:
    cases: list[ValidationCase] = []
    for poc in build_cases():
        matching_refs = tuple(ref for ref in source_refs if _matches_poc(ref, poc))
        if not matching_refs:
            continue
        cases.append(_poc_to_validation_case(poc, matching_refs, base_url))
    return tuple(cases)


def _matches_poc(ref: SourceReference, poc: PocCase) -> bool:
    if poc.source_path_hint and not ref.path.endswith(poc.source_path_hint):
        return False
    if ref.line not in poc.sink_lines:
        return False
    if ref.artifact_type == SCAN_ARTIFACT_TYPE:
        return ref.category in {"dsa.java.runtime-exec", "dsa.java.sql-concat"}
    if ref.artifact_type == JAVA_REST_VERIFICATION_ARTIFACT_TYPE:
        return ref.category in {"command-injection", "sql-injection"}
    return False


def _poc_to_validation_case(
    poc: PocCase,
    refs: tuple[SourceReference, ...],
    base_url: str,
) -> ValidationCase:
    command = curl_command(base_url, poc)
    steps = (
        ValidationStep(
            1,
            "Confirm the target is an approved development or test deployment and capture the change window or authorization reference.",
            "Human reviewer confirms this is in scope before any request is sent.",
        ),
        ValidationStep(
            2,
            "Send the benign validation request generated from the mapped source finding.",
            "The request reaches the mapped endpoint without using production credentials or destructive input.",
            command,
        ),
        ValidationStep(
            3,
            "Verify server-side evidence using the printed marker check or log review instruction.",
            "Evidence proves whether the request-controlled value reached the vulnerable execution path.",
            poc.server_verification,
        ),
        ValidationStep(
            4,
            "Capture HTTP response, server evidence, mapped source line, and remediation recommendation in the bug record.",
            "A human reviewer can reproduce the validation from the captured steps.",
        ),
    )
    return ValidationCase(
        case_id=f"siebel-sam-rest.{poc.case_id}",
        title=poc.title,
        category="command-injection" if "argument" not in poc.case_id else "argument-injection",
        severity=_max_severity(refs),
        source_refs=refs,
        steps=steps,
        safe_mode="benign-marker-validation",
        request_command=command,
        marker_file=poc.marker_file,
        manual_verification=poc.server_verification,
        notes=poc.notes,
    )


def _generic_cases(source_refs: tuple[SourceReference, ...]) -> tuple[ValidationCase, ...]:
    cases: list[ValidationCase] = []
    for index, ref in enumerate(source_refs, start=1):
        steps = (
            ValidationStep(
                1,
                "Map the source finding to a deployed component, endpoint, job, or integration path.",
                "A human reviewer identifies where this code is reachable in the running deployment.",
            ),
            ValidationStep(
                2,
                "Prepare a benign validation input that proves control-flow reachability without modifying data or exposing secrets.",
                "The payload is reviewed before execution and does not perform destructive actions.",
            ),
            ValidationStep(
                3,
                "Run the approved validation input against the explicitly authorized test deployment.",
                "The deployment response, logs, or audit records show whether the risky code path is reachable.",
            ),
            ValidationStep(
                4,
                "Record reproduction steps, observed evidence, scope, and recommended remediation.",
                "The bug record is actionable and reproducible by a human reviewer.",
            ),
        )
        cases.append(
            ValidationCase(
                case_id=f"generic.{index}",
                title=ref.title,
                category=ref.category,
                severity=ref.severity,
                source_refs=(ref,),
                steps=steps,
                safe_mode="manual-validation-plan",
                notes=(
                    "No repository-specific validator is available for this finding. "
                    "The agent produced a manual validation plan only."
                ),
            )
        )
    return tuple(cases)


def _execute_case(case: ValidationCase, base_url: str, timeout: int) -> ValidationCase:
    if case.case_id.startswith("http-probe."):
        return _execute_http_probe_case(case, base_url, timeout)

    poc = _poc_by_validation_case_id(case.case_id)
    if poc is None:
        return _replace_execution(
            case,
            ExecutionEvidence(
                status="blocked",
                note="No automated executor is registered for this validation case.",
            ),
        )
    status, body = execute_case(base_url, poc, timeout=timeout)
    if status is None:
        execution = ExecutionEvidence(
            status="network-error",
            response_preview=body[:1000],
            note="Request was not delivered; review target URL, network access, and service availability.",
        )
    else:
        execution = ExecutionEvidence(
            status="manual-verification-required",
            http_status=status,
            response_preview=body[:1000],
            note=(
                "HTTP request was sent. Confirm exploitability with the server-side "
                "verification step before filing as reproduced."
            ),
        )
    return _replace_execution(case, execution)


def _poc_by_validation_case_id(case_id: str) -> PocCase | None:
    prefix = "siebel-sam-rest."
    if not case_id.startswith(prefix):
        return None
    wanted = case_id[len(prefix) :]
    for poc in build_cases():
        if poc.case_id == wanted:
            return poc
    return None


def _replace_execution(case: ValidationCase, execution: ExecutionEvidence) -> ValidationCase:
    return ValidationCase(
        case_id=case.case_id,
        title=case.title,
        category=case.category,
        severity=case.severity,
        source_refs=case.source_refs,
        steps=case.steps,
        safe_mode=case.safe_mode,
        request_command=case.request_command,
        marker_file=case.marker_file,
        manual_verification=case.manual_verification,
        notes=case.notes,
        metadata=case.metadata,
        execution=execution,
    )


def _http_probe_cases(
    source_refs: tuple[SourceReference, ...],
    base_url: str,
    probe_spec_path: Path,
    aggressive_sandbox: bool,
    max_mutations_per_case: int,
) -> tuple[tuple[ValidationCase, ...], tuple[str, ...]]:
    spec = _load_probe_spec(probe_spec_path)
    notes: list[str] = []
    cases: list[ValidationCase] = []
    for raw_case in spec.get("cases", []):
        if not isinstance(raw_case, dict):
            notes.append("Ignored non-object probe case.")
            continue
        try:
            _validate_probe_case(raw_case)
        except ValueError as exc:
            notes.append(f"Ignored invalid probe case {raw_case.get('case_id', '<unknown>')}: {exc}")
            continue

        matching_refs = tuple(ref for ref in source_refs if _matches_probe_case(ref, raw_case))
        if not matching_refs:
            continue

        expanded_cases = _expanded_http_probe_cases(
            raw_case,
            matching_refs,
            base_url,
            aggressive_sandbox=aggressive_sandbox,
            max_mutations_per_case=max_mutations_per_case,
        )
        cases.extend(expanded_cases)

    if not cases:
        notes.append(
            "No HTTP probe cases matched the supplied artifact. Check probe match rule_ids, categories, tags, paths, and lines."
        )
    if aggressive_sandbox:
        notes.append(
            "Aggressive sandbox mode expanded reviewed probe specs into bounded payload variants. "
            "Payloads are limited to non-persistent, non-exfiltrating validation markers."
        )
    return tuple(cases), tuple(notes)


def _expanded_http_probe_cases(
    raw_case: dict[str, Any],
    matching_refs: tuple[SourceReference, ...],
    base_url: str,
    aggressive_sandbox: bool,
    max_mutations_per_case: int,
) -> list[ValidationCase]:
    variants = [(raw_case, "base", "base request")]
    if aggressive_sandbox:
        variants.extend(_mutated_probe_variants(raw_case, max_mutations_per_case))

    cases: list[ValidationCase] = []
    for variant_index, (variant_case, variant_id, variant_label) in enumerate(variants, start=1):
        request_command = _http_probe_curl(base_url, variant_case["request"])
        manual_verification = str(
            variant_case.get(
                "manual_verification",
                "Review response, logs, and audit records for expected evidence.",
            )
        )
        steps = (
            ValidationStep(
                1,
                "Confirm the deployment, account, and data set are approved for this validation case.",
                "Human reviewer confirms the probe is in scope for the DevOps-owned security sandbox.",
            ),
            ValidationStep(
                2,
                "Send the reviewed HTTP probe request to the sandbox deployment.",
                "The request reaches only the allowlisted sandbox host.",
                request_command,
            ),
            ValidationStep(
                3,
                "Compare the response and server-side telemetry with the expected indicators in the probe spec.",
                "The reviewer can decide whether the suspected vulnerability is reproduced.",
                manual_verification,
            ),
            ValidationStep(
                4,
                "Record mapped source evidence, request, response, logs, and remediation guidance in the bug.",
                "The bug is reproducible without requiring access to this tool.",
            ),
        )
        case_suffix = "" if variant_id == "base" else f".{variant_index:03d}.{variant_id}"
        cases.append(
            ValidationCase(
                case_id=f"http-probe.{raw_case['case_id']}{case_suffix}",
                title=f"{raw_case['title']} ({variant_label})",
                category=str(raw_case.get("category", "http-probe")),
                severity=str(raw_case.get("severity") or _max_severity(matching_refs)),
                source_refs=matching_refs,
                steps=steps,
                safe_mode=str(raw_case.get("safe_mode", "controlled-aggressive-http-probe" if aggressive_sandbox else "non-destructive-http-probe")),
                request_command=request_command,
                manual_verification=manual_verification,
                notes=str(raw_case.get("notes", "")),
                metadata={"http_probe": variant_case, "variant": variant_label},
            )
        )
    return cases


def _load_probe_spec(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("probe spec must be a JSON object")
    if payload.get("profile") != "dsa.http-probe.v1":
        raise ValueError("probe spec profile must be dsa.http-probe.v1")
    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise ValueError("probe spec must contain a cases list")
    return payload


def _validate_probe_case(raw_case: dict[str, Any]) -> None:
    for field_name in ("case_id", "title", "request", "match"):
        if field_name not in raw_case:
            raise ValueError(f"missing {field_name}")
    request = raw_case["request"]
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    method = str(request.get("method", "GET")).upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
        raise ValueError(f"unsupported HTTP method {method!r}")
    path = str(request.get("path", ""))
    if not path.startswith("/") or urlparse(path).scheme:
        raise ValueError("request.path must be a relative absolute path such as /siebel/v1/test")
    headers = request.get("headers", {})
    if headers is not None and not isinstance(headers, dict):
        raise ValueError("request.headers must be an object")
    if any(str(name).lower() == "host" for name in headers):
        raise ValueError("request.headers must not override Host")
    match = raw_case["match"]
    if not isinstance(match, dict) or not match:
        raise ValueError("match must be a non-empty object")
    mutations = raw_case.get("mutations", [])
    if mutations is not None:
        if not isinstance(mutations, list):
            raise ValueError("mutations must be a list")
        for mutation in mutations:
            _validate_mutation(mutation)


def _validate_mutation(mutation: Any) -> None:
    if not isinstance(mutation, dict):
        raise ValueError("mutation must be an object")
    location = mutation.get("location")
    if location not in {"query", "json", "header", "body", "path"}:
        raise ValueError("mutation.location must be query, json, header, body, or path")
    payload_set = str(mutation.get("payload_set", ""))
    if payload_set not in PAYLOAD_SETS:
        raise ValueError(f"unsupported mutation payload_set {payload_set!r}")
    if location in {"query", "json", "header"} and not mutation.get("name"):
        raise ValueError(f"mutation.name is required for {location}")
    if location in {"body", "path"} and not mutation.get("placeholder"):
        raise ValueError(f"mutation.placeholder is required for {location}")


def _mutated_probe_variants(
    raw_case: dict[str, Any],
    max_mutations_per_case: int,
) -> list[tuple[dict[str, Any], str, str]]:
    variants: list[tuple[dict[str, Any], str, str]] = []
    mutations = raw_case.get("mutations", []) or []
    for mutation in mutations:
        payload_set_name = str(mutation["payload_set"])
        for payload_index, payload in enumerate(PAYLOAD_SETS[payload_set_name], start=1):
            if len(variants) >= max_mutations_per_case:
                return variants
            mutated = deepcopy(raw_case)
            mutated["request"] = _apply_mutation(mutated["request"], mutation, payload)
            mutated.setdefault("expected", _default_expected_for_payload_set(payload_set_name))
            variant_id = f"{payload_set_name}.{payload_index}"
            variant_label = f"{payload_set_name} payload {payload_index}"
            variants.append((mutated, _slug(variant_id), variant_label))
    return variants


def _apply_mutation(request: dict[str, Any], mutation: dict[str, Any], payload: str) -> dict[str, Any]:
    request = deepcopy(request)
    location = mutation["location"]
    if location == "query":
        query = dict(request.get("query") or {})
        query[str(mutation["name"])] = payload
        request["query"] = query
    elif location == "json":
        body = dict(request.get("json") or {})
        body[str(mutation["name"])] = payload
        request["json"] = body
    elif location == "header":
        headers = dict(request.get("headers") or {})
        headers[str(mutation["name"])] = payload
        request["headers"] = headers
    elif location == "body":
        body_text = str(request.get("body", ""))
        request["body"] = body_text.replace(str(mutation["placeholder"]), payload)
    elif location == "path":
        path = str(request.get("path", ""))
        request["path"] = path.replace(str(mutation["placeholder"]), payload)
    return request


def _default_expected_for_payload_set(payload_set_name: str) -> dict[str, Any]:
    if payload_set_name == "xss-reflection":
        return {"body_contains_any": ["DSA_PROBE", "<script", "onload", "onerror"]}
    if payload_set_name == "command-injection-marker":
        return {"body_contains_any": ["DSA_PROBE"]}
    if payload_set_name == "path-traversal-canary":
        return {"body_contains_any": ["DSA_CANARY"]}
    if payload_set_name == "xml-parser-marker":
        return {"body_contains_any": ["DSA_PROBE", "DOCTYPE", "ENTITY"]}
    return {"status_codes": [200, 400, 401, 403, 404, 500]}


def _slug(value: str) -> str:
    safe = []
    for char in value.lower():
        if char.isalnum() or char in {".", "-"}:
            safe.append(char)
        else:
            safe.append("-")
    return "".join(safe).strip("-")


def _matches_probe_case(ref: SourceReference, raw_case: dict[str, Any]) -> bool:
    match = raw_case.get("match", {})
    rule_ids = _string_set(match.get("rule_ids"))
    categories = _string_set(match.get("categories"))
    tags_any = _string_set(match.get("tags_any"))
    path_contains = tuple(str(item) for item in match.get("path_contains", []) or [])
    lines = {int(item) for item in match.get("lines", []) or []}

    matched = False
    if rule_ids:
        if ref.category not in rule_ids:
            return False
        matched = True
    if categories:
        if ref.category not in categories:
            return False
        matched = True
    if tags_any:
        if not tags_any.intersection(ref.tags):
            return False
        matched = True
    if path_contains:
        if not any(fragment in ref.path for fragment in path_contains):
            return False
        matched = True
    if lines:
        if ref.line not in lines:
            return False
        matched = True
    return matched


def _string_set(value: Any) -> set[str]:
    if not value:
        return set()
    if isinstance(value, str):
        return {value}
    return {str(item) for item in value}


def _http_probe_curl(base_url: str, request: dict[str, Any]) -> str:
    method = str(request.get("method", "GET")).upper()
    url = _http_probe_url(base_url, request)
    parts = ["curl", "-i", "-X", method]
    for name, value in (request.get("headers") or {}).items():
        parts.extend(["-H", f"{name}: {value}"])
    if "json" in request:
        parts.extend(["-H", "Content-Type: application/json"])
        parts.extend(["--data", json.dumps(request["json"], separators=(",", ":"))])
    elif "body" in request:
        parts.extend(["--data", str(request["body"])])
    parts.append(url)
    return " ".join(shlex.quote(part) for part in parts)


def _http_probe_url(base_url: str, request: dict[str, Any]) -> str:
    url = f"{base_url.rstrip('/')}{request['path']}"
    query = request.get("query")
    if isinstance(query, dict) and query:
        url = f"{url}?{urlencode(query, doseq=True)}"
    return url


def _execute_http_probe_case(
    case: ValidationCase,
    base_url: str,
    timeout: int,
) -> ValidationCase:
    raw_case = case.metadata.get("http_probe")
    if not isinstance(raw_case, dict):
        return _replace_execution(
            case,
            ExecutionEvidence(status="blocked", note="HTTP probe metadata is missing."),
        )
    request = raw_case["request"]
    method = str(request.get("method", "GET")).upper()
    headers = {str(name): str(value) for name, value in (request.get("headers") or {}).items()}
    data = None
    if "json" in request:
        headers.setdefault("Content-Type", "application/json")
        data = json.dumps(request["json"]).encode("utf-8")
    elif "body" in request:
        data = str(request["body"]).encode("utf-8")
    req = urllib.request.Request(
        _http_probe_url(base_url, request),
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(2000).decode("utf-8", errors="replace")
            http_status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read(2000).decode("utf-8", errors="replace")
        http_status = exc.code
    except urllib.error.URLError as exc:
        return _replace_execution(
            case,
            ExecutionEvidence(
                status="network-error",
                response_preview=str(exc)[:1000],
                note="Request was not delivered; review target URL, network access, and service availability.",
            ),
        )

    expected_note = _expected_indicator_note(raw_case.get("expected", {}), http_status, body)
    return _replace_execution(
        case,
        ExecutionEvidence(
            status="manual-verification-required",
            http_status=http_status,
            response_preview=body[:1000],
            note=f"HTTP probe was sent. {expected_note} Human review is required before filing as reproduced.",
        ),
    )


def _expected_indicator_note(expected: Any, http_status: int, body: str) -> str:
    if not isinstance(expected, dict) or not expected:
        return "No expected indicators were configured."
    indicators: list[str] = []
    status_codes = expected.get("status_codes")
    if isinstance(status_codes, list) and status_codes:
        indicators.append(
            "status matched" if http_status in {int(item) for item in status_codes} else "status did not match"
        )
    body_contains_any = expected.get("body_contains_any")
    if isinstance(body_contains_any, list) and body_contains_any:
        indicators.append(
            "body indicator matched"
            if any(str(item) in body for item in body_contains_any)
            else "body indicator did not match"
        )
    return "; ".join(indicators) + "." if indicators else "No supported expected indicators were configured."


def _max_severity(refs: tuple[SourceReference, ...]) -> str:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return min((ref.severity for ref in refs), key=lambda severity: order.get(severity, 99))


def _case_to_dict(case: ValidationCase) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "title": case.title,
        "category": case.category,
        "severity": case.severity,
        "safe_mode": case.safe_mode,
        "request_command": case.request_command,
        "marker_file": case.marker_file,
        "manual_verification": case.manual_verification,
        "notes": case.notes,
        "source_refs": [
            {
                "artifact_type": ref.artifact_type,
                "ref_id": ref.ref_id,
                "title": ref.title,
                "category": ref.category,
                "severity": ref.severity,
                "path": ref.path,
                "line": ref.line,
                "evidence": ref.evidence,
                "tags": list(ref.tags),
            }
            for ref in case.source_refs
        ],
        "steps": [
            {
                "order": step.order,
                "action": step.action,
                "expected_result": step.expected_result,
                "command": step.command,
            }
            for step in case.steps
        ],
        "execution": {
            "status": case.execution.status,
            "http_status": case.execution.http_status,
            "response_preview": case.execution.response_preview,
            "note": case.execution.note,
        },
        "metadata": case.metadata,
    }

from __future__ import annotations

from collections import Counter

from .validation import DeploymentValidationResult, ValidationCase


def render_validation_markdown(result: DeploymentValidationResult) -> str:
    mode = "execute" if result.executed else "dry-run"
    lines: list[str] = [
        "# Defensive Security Agent Validation Report",
        "",
        f"- Artifact: `{result.artifact_path}`",
        f"- Artifact type: `{result.artifact_type}`",
        f"- Target deployment: `{result.base_url}`",
        f"- Profile: `{result.profile}`",
        f"- Mode: `{mode}`",
        f"- Aggressive sandbox expansion: `{result.aggressive_sandbox}`",
        f"- Validation cases: {len(result.cases)}",
        "",
        "## Safety Controls",
        "",
        "- Execution is dry-run by default.",
        "- Live requests require explicit authorization acknowledgement and target host allowlisting.",
        "- Built-in automated cases use benign marker or argument-validation probes.",
        "- Aggressive sandbox mode expands reviewed probe specs into bounded validation markers.",
        "- Server-side success must be confirmed by a human reviewer before filing as reproduced.",
        "",
    ]

    if result.notes:
        lines.extend(["## Notes", ""])
        for note in result.notes:
            lines.append(f"- {note}")
        lines.append("")

    if not result.cases:
        lines.extend(["## Validation Cases", "", "No validation cases were generated.", ""])
        return "\n".join(lines)

    counts = Counter(case.execution.status for case in result.cases)
    lines.extend(["## Execution Summary", ""])
    for status, count in sorted(counts.items()):
        lines.append(f"- {status}: {count}")
    lines.append("")

    lines.extend(["## Validation Cases", ""])
    for index, case in enumerate(result.cases, start=1):
        lines.extend(_case_lines(index, case))
    return "\n".join(lines)


def _case_lines(index: int, case: ValidationCase) -> list[str]:
    lines: list[str] = [
        f"### {index}. {case.title}",
        "",
        f"- Case ID: `{case.case_id}`",
        f"- Category: `{case.category}`",
        f"- Severity: `{case.severity}`",
        f"- Safe mode: `{case.safe_mode}`",
        f"- Execution status: `{case.execution.status}`",
    ]
    if case.execution.http_status is not None:
        lines.append(f"- HTTP status: `{case.execution.http_status}`")
    if case.marker_file:
        lines.append(f"- Marker file: `{case.marker_file}`")
    if case.manual_verification:
        lines.append(f"- Manual verification: `{case.manual_verification}`")
    if case.notes:
        lines.append(f"- Notes: {case.notes}")
    if case.execution.note:
        lines.append(f"- Execution note: {case.execution.note}")
    expected = _expected_indicators(case)
    if expected:
        lines.append(f"- Expected indicators: {expected}")
    lines.append(f"- Bug filing recommendation: {_bug_filing_recommendation(case)}")
    lines.append("")

    lines.extend(["Source evidence:", ""])
    for ref in case.source_refs:
        lines.extend(
            [
                f"- `{ref.path}:{ref.line}` `{ref.category}` `{ref.severity}`",
                "",
                "```text",
                ref.evidence[:400],
                "```",
                "",
            ]
        )

    lines.extend(["Validation steps:", ""])
    for step in case.steps:
        lines.append(f"{step.order}. {step.action}")
        lines.append(f"   Expected result: {step.expected_result}")
        if step.command:
            lines.extend(["", "```bash", step.command, "```", ""])

    if case.execution.response_preview:
        lines.extend(
            [
                "Actual result / response preview:",
                "",
                "```text",
                case.execution.response_preview[:1000],
                "```",
                "",
            ]
        )
    lines.append("")
    return lines


def _bug_filing_recommendation(case: ValidationCase) -> str:
    if case.execution.status == "planned":
        return "Do not file as reproduced yet; use this as the approved validation plan."
    if case.execution.status == "network-error":
        return "Do not file as reproduced; the request did not reach the sandbox target."
    if case.execution.status == "blocked":
        return "Do not file as reproduced; no approved automated validation was available."
    if case.execution.status == "manual-verification-required":
        return (
            "File a bug if the human reviewer confirms the expected indicator or "
            "server-side evidence; otherwise keep as inconclusive."
        )
    return "Needs human review."


def _expected_indicators(case: ValidationCase) -> str:
    probe = case.metadata.get("http_probe") if case.metadata else None
    if not isinstance(probe, dict):
        return ""
    expected = probe.get("expected")
    if not isinstance(expected, dict) or not expected:
        return ""
    parts: list[str] = []
    if expected.get("status_codes"):
        parts.append(f"status in {expected['status_codes']}")
    if expected.get("body_contains_any"):
        parts.append(f"body contains any of {expected['body_contains_any']}")
    return "; ".join(parts)

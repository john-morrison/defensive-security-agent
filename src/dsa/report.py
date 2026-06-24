from __future__ import annotations

from collections import Counter

from .findings import SEVERITY_ORDER, ScanResult


def render_markdown(result: ScanResult) -> str:
    lines: list[str] = [
        "# Defensive Security Agent Report",
        "",
        f"- Target: `{result.target}`",
        f"- Scanned files: {result.scanned_files}",
        f"- Skipped files: {result.skipped_files}",
        f"- Findings: {len(result.findings)}",
        "",
    ]

    if result.tool_notes:
        lines.extend(["## Tool Notes", ""])
        for note in result.tool_notes:
            lines.append(f"- {note}")
        lines.append("")

    if not result.findings:
        lines.extend(["## Findings", "", "No potential issues found.", ""])
        return "\n".join(lines)

    counts = Counter(finding.severity for finding in result.findings)
    lines.extend(["## Severity Summary", ""])
    for severity in sorted(counts, key=lambda item: SEVERITY_ORDER[item]):
        lines.append(f"- {severity}: {counts[severity]}")
    lines.append("")

    lines.extend(["## Findings", ""])
    for index, finding in enumerate(result.findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding.title}",
                "",
                f"- Severity: `{finding.severity}`",
                f"- Rule: `{finding.rule_id}`",
                f"- Source: `{finding.source}`",
                f"- Location: `{finding.path}:{finding.line}`",
                f"- Tags: `{', '.join(finding.tags) if finding.tags else 'none'}`",
                "",
                "Evidence:",
                "",
                "```text",
                finding.evidence,
                "```",
                "",
                f"Why it matters: {finding.rationale}",
                "",
                f"Recommended action: {finding.recommendation}",
                "",
            ]
        )

    return "\n".join(lines)


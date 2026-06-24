from __future__ import annotations

from collections import Counter

from .java_rest_verifier import VerificationResult


def render_verification_markdown(result: VerificationResult) -> str:
    lines: list[str] = [
        "# Java REST Verification Report",
        "",
        f"- Target: `{result.target}`",
        f"- Scanned Java files: {result.scanned_files}",
        f"- Source-to-sink traces: {len(result.traces)}",
        "",
    ]

    if result.notes:
        lines.extend(["## Notes", ""])
        for note in result.notes:
            lines.append(f"- {note}")
        lines.append("")

    if not result.traces:
        lines.extend(["## Traces", "", "No REST source-to-sink traces found.", ""])
        return "\n".join(lines)

    status_counts = Counter(trace.status for trace in result.traces)
    class_counts = Counter(trace.bug_class for trace in result.traces)

    lines.extend(["## Status Summary", ""])
    for status, count in sorted(status_counts.items()):
        lines.append(f"- {status}: {count}")
    lines.append("")

    lines.extend(["## Bug Class Summary", ""])
    for bug_class, count in sorted(class_counts.items()):
        lines.append(f"- {bug_class}: {count}")
    lines.append("")

    lines.extend(["## Traces", ""])
    for index, trace in enumerate(result.traces, start=1):
        lines.extend(
            [
                f"### {index}. {trace.bug_class} in `{trace.method_name}`",
                "",
                f"- Status: `{trace.status}`",
                f"- Location: `{trace.path}:{trace.sink_line}`",
                f"- Method starts: `{trace.path}:{trace.method_line}`",
                f"- Source line: `{trace.path}:{trace.source_line}`",
                f"- Tainted symbols: `{', '.join(trace.tainted_symbols) if trace.tainted_symbols else 'request expression'}`",
                "",
                "Source evidence:",
                "",
                "```text",
                trace.source_evidence,
                "```",
                "",
                "Sink evidence:",
                "",
                "```text",
                trace.sink_evidence,
                "```",
                "",
            ]
        )
        if trace.guard_evidence:
            lines.extend(["Guard evidence found:", ""])
            for guard in trace.guard_evidence:
                lines.append(f"- `{guard}`")
            lines.append("")
        lines.extend(
            [
                f"Why it matters: {trace.rationale}",
                "",
                f"Recommended action: {trace.recommendation}",
                "",
            ]
        )

    return "\n".join(lines)


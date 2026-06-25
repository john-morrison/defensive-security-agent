from __future__ import annotations

import argparse
from pathlib import Path

from .artifacts import (
    scan_result_to_artifact,
    verification_result_to_artifact,
    write_artifact,
)
from .java_rest_verifier import verify_java_rest_target
from .report import render_markdown
from .scanner import scan_target
from .triage_report import render_verification_markdown
from .validation import validate_artifact, write_validation_json
from .validation_report import render_validation_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dsa",
        description="Run defensive security checks against a local source tree.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a local repository or directory")
    scan.add_argument("--target", required=True, help="directory or file to scan")
    scan.add_argument(
        "--output",
        default="security-report.md",
        help="Markdown report path",
    )
    scan.add_argument(
        "--json-output",
        help="optional JSON artifact path for downstream validation",
    )
    scan.add_argument(
        "--include-semgrep",
        action="store_true",
        help="run Semgrep when the semgrep CLI is available",
    )
    scan.add_argument(
        "--max-file-kb",
        type=int,
        default=512,
        help="skip files larger than this size",
    )

    triage = subparsers.add_parser(
        "triage",
        help="verify source-to-sink candidates for a supported target kind",
    )
    triage.add_argument("--target", required=True, help="directory or file to triage")
    triage.add_argument(
        "--kind",
        choices=("java-rest",),
        default="java-rest",
        help="verification workflow to run",
    )
    triage.add_argument(
        "--output",
        default="verification-report.md",
        help="Markdown verification report path",
    )
    triage.add_argument(
        "--json-output",
        help="optional JSON artifact path for downstream validation",
    )
    triage.add_argument(
        "--max-file-kb",
        type=int,
        default=512,
        help="skip files larger than this size",
    )

    validate = subparsers.add_parser(
        "validate",
        help="build or run authorized deployment validation from a scan or triage artifact",
    )
    validate.add_argument(
        "--findings",
        required=True,
        help="JSON artifact from `dsa scan --json-output` or `dsa triage --json-output`",
    )
    validate.add_argument(
        "--base-url",
        required=True,
        help="authorized test deployment base URL",
    )
    validate.add_argument(
        "--profile",
        choices=("generic", "siebel-sam-rest", "http-probe"),
        default="generic",
        help="validation profile to apply",
    )
    validate.add_argument(
        "--probe-spec",
        help="JSON probe specification for --profile http-probe",
    )
    validate.add_argument(
        "--output",
        default="validation-report.md",
        help="Markdown validation report path",
    )
    validate.add_argument(
        "--json-output",
        help="optional JSON validation report path",
    )
    validate.add_argument(
        "--execute",
        action="store_true",
        help="send safe validation requests instead of producing a dry-run plan",
    )
    validate.add_argument(
        "--aggressive-sandbox",
        action="store_true",
        help="expand reviewed HTTP probe specs into bounded payload variants for a controlled sandbox",
    )
    validate.add_argument(
        "--max-mutations-per-case",
        type=int,
        default=25,
        help="maximum generated payload variants per HTTP probe case",
    )
    validate.add_argument(
        "--i-understand-authorized-test",
        action="store_true",
        help="required with --execute; confirms the target is authorized for testing",
    )
    validate.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="host that may receive validation requests; repeat for multiple hosts",
    )
    validate.add_argument("--timeout", type=int, default=20, help="HTTP timeout in seconds")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        target = Path(args.target).resolve()
        output = Path(args.output).resolve()
        result = scan_target(
            target=target,
            include_semgrep=args.include_semgrep,
            max_file_kb=args.max_file_kb,
        )
        output.write_text(render_markdown(result), encoding="utf-8")
        if args.json_output:
            write_artifact(Path(args.json_output).resolve(), scan_result_to_artifact(result))
        print(f"Wrote {output}")
        if args.json_output:
            print(f"Wrote {Path(args.json_output).resolve()}")
        if result.findings:
            print(f"Found {len(result.findings)} potential issue(s)")
        else:
            print("No potential issues found")
        return 0

    if args.command == "triage":
        target = Path(args.target).resolve()
        output = Path(args.output).resolve()
        if args.kind == "java-rest":
            result = verify_java_rest_target(target=target, max_file_kb=args.max_file_kb)
            output.write_text(render_verification_markdown(result), encoding="utf-8")
            if args.json_output:
                write_artifact(
                    Path(args.json_output).resolve(),
                    verification_result_to_artifact(result),
                )
            print(f"Wrote {output}")
            if args.json_output:
                print(f"Wrote {Path(args.json_output).resolve()}")
            if result.traces:
                print(f"Found {len(result.traces)} source-to-sink trace(s)")
            else:
                print("No source-to-sink traces found")
            return 0

    if args.command == "validate":
        if args.execute and not args.i_understand_authorized_test:
            parser.error("--execute requires --i-understand-authorized-test")
        findings = Path(args.findings).resolve()
        output = Path(args.output).resolve()
        result = validate_artifact(
            artifact_path=findings,
            base_url=args.base_url,
            profile=args.profile,
            execute=args.execute,
            allow_hosts=tuple(args.allow_host),
            timeout=args.timeout,
            probe_spec_path=Path(args.probe_spec).resolve() if args.probe_spec else None,
            aggressive_sandbox=args.aggressive_sandbox,
            max_mutations_per_case=args.max_mutations_per_case,
        )
        output.write_text(render_validation_markdown(result), encoding="utf-8")
        if args.json_output:
            write_validation_json(Path(args.json_output).resolve(), result)
        print(f"Wrote {output}")
        if args.json_output:
            print(f"Wrote {Path(args.json_output).resolve()}")
        print(f"Generated {len(result.cases)} validation case(s)")
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2

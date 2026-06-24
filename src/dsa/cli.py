from __future__ import annotations

import argparse
from pathlib import Path

from .java_rest_verifier import verify_java_rest_target
from .report import render_markdown
from .scanner import scan_target
from .triage_report import render_verification_markdown


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
        "--max-file-kb",
        type=int,
        default=512,
        help="skip files larger than this size",
    )

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
        print(f"Wrote {output}")
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
            print(f"Wrote {output}")
            if result.traces:
                print(f"Found {len(result.traces)} source-to-sink trace(s)")
            else:
                print("No source-to-sink traces found")
            return 0

    parser.error(f"unknown command: {args.command}")
    return 2

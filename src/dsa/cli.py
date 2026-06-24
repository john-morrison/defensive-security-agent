from __future__ import annotations

import argparse
from pathlib import Path

from .report import render_markdown
from .scanner import scan_target


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

    parser.error(f"unknown command: {args.command}")
    return 2


#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dsa.siebel_sam_rest_pocs import (  # noqa: E402
    DEFAULT_BASE_URL,
    build_cases,
    build_url,
    curl_command,
    execute_case,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate or run safe PoC requests for SAMRESTServices command-injection findings. "
            "Dry-run is the default."
        )
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="SAM REST base URL, for example http://host:port/bugdb")
    parser.add_argument("--case", choices=[case.case_id for case in build_cases()], help="run or print only one case")
    parser.add_argument("--execute", action="store_true", help="send HTTP requests instead of printing them")
    parser.add_argument(
        "--i-understand-authorized-test",
        action="store_true",
        help="required with --execute; confirms this is an authorized dev/test target",
    )
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout in seconds")
    args = parser.parse_args(argv)

    if args.execute and not args.i_understand_authorized_test:
        print("--execute requires --i-understand-authorized-test", file=sys.stderr)
        return 2

    cases = build_cases()
    if args.case:
        cases = tuple(case for case in cases if case.case_id == args.case)

    for case in cases:
        print(f"\n## {case.case_id}: {case.title}")
        print(f"Trace: {case.trace_location}")
        print(f"Notes: {case.notes}")
        print(f"Marker file: {case.marker_file}")
        print(f"Server verification: {case.server_verification}")
        print("Request:")
        print(curl_command(args.base_url, case))
        if args.execute:
            status, body = execute_case(args.base_url, case, timeout=args.timeout)
            print(f"HTTP status: {status}")
            if body:
                print("Response preview:")
                print(body[:1000])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

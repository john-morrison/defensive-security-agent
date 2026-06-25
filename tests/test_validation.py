from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dsa.artifacts import load_artifact, scan_result_to_artifact, write_artifact
from dsa.scanner import scan_target
from dsa.validation import validate_artifact


class ValidationTests(unittest.TestCase):
    def test_scan_artifact_feeds_siebel_sam_rest_validation_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            source = target / "RestController.java"
            source.write_text(
                "\n".join(
                    [
                        "class RestController {",
                        "  void filler() {",
                        *["    int x = 1;" for _ in range(580)],
                        '    Runtime.getRuntime().exec("cmd /c tool " + owner);',
                        "  }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            result = scan_target(target, include_semgrep=False, max_file_kb=512)
            artifact_path = target / "scan.json"
            write_artifact(artifact_path, scan_result_to_artifact(result))

            validation = validate_artifact(
                artifact_path=artifact_path,
                base_url="http://localhost:8080/bugdb",
                profile="siebel-sam-rest",
            )

        self.assertEqual(len(validation.cases), 1)
        case = validation.cases[0]
        self.assertEqual(case.case_id, "siebel-sam-rest.workspace")
        self.assertIn("curl -i", case.request_command)
        self.assertIn("%26", case.request_command)
        self.assertNotIn(" & ", case.request_command)
        self.assertEqual(case.execution.status, "planned")

    def test_validate_execute_requires_allowlisted_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = {
                "artifact_type": "dsa.scan.v1",
                "schema_version": 1,
                "target": tmp,
                "scanned_files": 1,
                "skipped_files": 0,
                "tool_notes": [],
                "findings": [],
            }
            artifact_path = Path(tmp) / "scan.json"
            write_artifact(artifact_path, artifact)

            with self.assertRaisesRegex(ValueError, "not in --allow-host"):
                validate_artifact(
                    artifact_path=artifact_path,
                    base_url="http://localhost:8080/bugdb",
                    profile="generic",
                    execute=True,
                    allow_hosts=("example.com",),
                )

    def test_generic_validation_creates_manual_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = {
                "artifact_type": "dsa.scan.v1",
                "schema_version": 1,
                "target": tmp,
                "scanned_files": 1,
                "skipped_files": 0,
                "tool_notes": [],
                "findings": [
                    {
                        "id": "finding-1",
                        "rule_id": "dsa.shell.shell-true",
                        "title": "Shell command execution with shell=True",
                        "severity": "high",
                        "path": str(Path(tmp) / "app.py"),
                        "line": 10,
                        "evidence": "subprocess.run(value, shell=True)",
                    }
                ],
            }
            artifact_path = Path(tmp) / "scan.json"
            write_artifact(artifact_path, artifact)

            validation = validate_artifact(
                artifact_path=artifact_path,
                base_url="https://test.example.invalid",
                profile="generic",
            )

        self.assertEqual(len(validation.cases), 1)
        self.assertEqual(validation.cases[0].safe_mode, "manual-validation-plan")
        self.assertEqual(validation.cases[0].execution.status, "planned")

    def test_http_probe_profile_builds_case_from_spec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            artifact_path = tmp_path / "scan.json"
            write_artifact(
                artifact_path,
                {
                    "artifact_type": "dsa.scan.v1",
                    "schema_version": 1,
                    "target": tmp,
                    "scanned_files": 1,
                    "skipped_files": 0,
                    "tool_notes": [],
                    "findings": [
                        {
                            "id": "finding-1",
                            "rule_id": "dsa.web.debug-mode",
                            "title": "Debug mode may be enabled",
                            "severity": "medium",
                            "path": str(tmp_path / "app.py"),
                            "line": 35,
                            "evidence": "app.run(debug=True)",
                            "tags": ["configuration", "web"],
                        }
                    ],
                },
            )
            spec_path = tmp_path / "probes.json"
            write_artifact_like_json(
                spec_path,
                {
                    "profile": "dsa.http-probe.v1",
                    "cases": [
                        {
                            "case_id": "debug.stacktrace",
                            "title": "Debug stack trace exposure probe",
                            "category": "debug-exposure",
                            "match": {"rule_ids": ["dsa.web.debug-mode"]},
                            "request": {
                                "method": "GET",
                                "path": "/debug/probe",
                                "query": {"trigger": "safe-error"},
                            },
                            "expected": {
                                "status_codes": [500],
                                "body_contains_any": ["Traceback"],
                            },
                            "manual_verification": "Confirm whether a stack trace or framework debugger is exposed.",
                        }
                    ],
                },
            )

            validation = validate_artifact(
                artifact_path=artifact_path,
                base_url="https://sandbox.example.test",
                profile="http-probe",
                probe_spec_path=spec_path,
            )

        self.assertEqual(len(validation.cases), 1)
        case = validation.cases[0]
        self.assertEqual(case.case_id, "http-probe.debug.stacktrace")
        self.assertIn("/debug/probe", case.request_command)
        self.assertIn("trigger=safe-error", case.request_command)
        self.assertEqual(case.execution.status, "planned")

    def test_aggressive_http_probe_expands_mutation_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            artifact_path = tmp_path / "scan.json"
            write_artifact(
                artifact_path,
                {
                    "artifact_type": "dsa.scan.v1",
                    "schema_version": 1,
                    "target": tmp,
                    "scanned_files": 1,
                    "skipped_files": 0,
                    "tool_notes": [],
                    "findings": [
                        {
                            "id": "finding-1",
                            "rule_id": "dsa.sql.string-interpolation",
                            "title": "Possible SQL query construction",
                            "severity": "high",
                            "path": str(tmp_path / "app.py"),
                            "line": 16,
                            "evidence": "db.execute(f\"select * from t where q={q}\")",
                            "tags": ["injection", "database"],
                        }
                    ],
                },
            )
            spec_path = tmp_path / "probes.json"
            write_artifact_like_json(
                spec_path,
                {
                    "profile": "dsa.http-probe.v1",
                    "cases": [
                        {
                            "case_id": "input.sqli",
                            "title": "SQL input sweep",
                            "category": "input-validation",
                            "match": {"tags_any": ["injection"]},
                            "request": {
                                "method": "GET",
                                "path": "/search",
                                "query": {"q": "baseline"},
                            },
                            "mutations": [
                                {
                                    "location": "query",
                                    "name": "q",
                                    "payload_set": "sqli-basic",
                                }
                            ],
                        }
                    ],
                },
            )

            validation = validate_artifact(
                artifact_path=artifact_path,
                base_url="https://sandbox.example.test",
                profile="http-probe",
                probe_spec_path=spec_path,
                aggressive_sandbox=True,
                max_mutations_per_case=2,
            )

        self.assertEqual(len(validation.cases), 3)
        self.assertTrue(validation.aggressive_sandbox)
        self.assertEqual(validation.cases[0].case_id, "http-probe.input.sqli")
        self.assertIn("q=baseline", validation.cases[0].request_command)
        self.assertIn("q=%27", validation.cases[1].request_command)
        self.assertIn("q=%22", validation.cases[2].request_command)

    def test_http_probe_profile_requires_spec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "scan.json"
            write_artifact(
                artifact_path,
                {
                    "artifact_type": "dsa.scan.v1",
                    "schema_version": 1,
                    "target": tmp,
                    "scanned_files": 0,
                    "skipped_files": 0,
                    "tool_notes": [],
                    "findings": [],
                },
            )

            with self.assertRaisesRegex(ValueError, "--probe-spec is required"):
                validate_artifact(
                    artifact_path=artifact_path,
                    base_url="https://sandbox.example.test",
                    profile="http-probe",
                )

    def test_load_artifact_rejects_unknown_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unknown.json"
            path.write_text('{"artifact_type":"unknown"}', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "unsupported artifact type"):
                load_artifact(path)


if __name__ == "__main__":
    unittest.main()


def write_artifact_like_json(path: Path, payload: dict) -> None:
    import json

    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

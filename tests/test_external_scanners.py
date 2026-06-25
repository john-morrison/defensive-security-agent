from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dsa.external_scanners import parse_bandit, parse_npm_audit, parse_semgrep
from dsa.findings import Finding
from dsa.scanner import scan_target


class ExternalScannerParserTests(unittest.TestCase):
    def test_parse_semgrep_result(self) -> None:
        payload = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.dangerous-subprocess-use",
                    "path": "app.py",
                    "start": {"line": 12},
                    "extra": {
                        "message": "Dangerous subprocess use",
                        "severity": "ERROR",
                        "lines": "subprocess.run(cmd, shell=True)",
                        "metadata": {"fix": "Use shell=False."},
                    },
                }
            ]
        }

        findings = parse_semgrep(Path("."), payload)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source, "semgrep")
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].line, 12)

    def test_parse_bandit_result(self) -> None:
        payload = {
            "results": [
                {
                    "test_id": "B602",
                    "test_name": "subprocess_popen_with_shell_equals_true",
                    "issue_severity": "HIGH",
                    "filename": "app.py",
                    "line_number": 20,
                    "code": "subprocess.Popen(cmd, shell=True)",
                    "issue_text": "subprocess call with shell=True identified",
                }
            ]
        }

        findings = parse_bandit(Path("."), payload)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source, "bandit")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].rule_id, "bandit.B602")

    def test_parse_npm_audit_result(self) -> None:
        payload = {
            "vulnerabilities": {
                "minimist": {
                    "name": "minimist",
                    "severity": "high",
                    "title": "Prototype pollution",
                    "fixAvailable": True,
                }
            }
        }

        findings = parse_npm_audit(Path("."), payload)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source, "npm-audit")
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("dependency", findings[0].tags)


class ExternalScannerIntegrationTests(unittest.TestCase):
    def test_scan_target_merges_external_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            source = target / "app.py"
            source.write_text("print('ok')\n", encoding="utf-8")
            external_finding = Finding(
                rule_id="semgrep.test",
                title="External scanner finding",
                severity="medium",
                path=source,
                line=1,
                evidence="print('ok')",
                rationale="test",
                recommendation="test",
                source="semgrep",
                tags=("semgrep",),
            )

            with patch(
                "dsa.scanner.run_external_scanners",
                return_value=([external_finding], ["external note"]),
            ) as run_external:
                result = scan_target(
                    target,
                    include_semgrep=False,
                    max_file_kb=512,
                    external_scanners=("semgrep",),
                )

        run_external.assert_called_once()
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].source, "semgrep")
        self.assertEqual(result.tool_notes, ("external note",))


if __name__ == "__main__":
    unittest.main()

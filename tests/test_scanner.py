from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dsa.scanner import scan_target


class ScannerTests(unittest.TestCase):
    def test_detects_builtin_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            source = target / "app.py"
            source.write_text(
                "\n".join(
                    [
                        "import subprocess",
                        "token = '1234567890123456'",
                        "subprocess.run(user_input, shell=True)",
                    ]
                ),
                encoding="utf-8",
            )

            result = scan_target(target, include_semgrep=False, max_file_kb=512)

        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertIn("dsa.shell.shell-true", rule_ids)
        self.assertEqual(result.scanned_files, 1)

    def test_skips_large_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            source = target / "large.py"
            source.write_text("x = 'a'\n" * 1000, encoding="utf-8")

            result = scan_target(target, include_semgrep=False, max_file_kb=1)

        self.assertEqual(result.scanned_files, 0)
        self.assertEqual(result.skipped_files, 1)


if __name__ == "__main__":
    unittest.main()

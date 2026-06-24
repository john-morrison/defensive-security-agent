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

    def test_detects_cpp_siebel_mvp_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            source = target / "BusinessService.cpp"
            source.write_text(
                "\n".join(
                    [
                        "#include <cstdlib>",
                        "void exportFile(const char* name) {",
                        "  char command[512];",
                        '  sprintf(command, "zip %s", name);',
                        "  system(command);",
                        "  char buffer[64];",
                        "  strcpy(buffer, name);",
                        '  std::string sql = "select * from S_ORG_EXT where ROW_ID = \'" + id + "\'";',
                        "  auto value = new Account();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            result = scan_target(target, include_semgrep=False, max_file_kb=512)

        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertIn("dsa.cpp.unsafe-format", rule_ids)
        self.assertIn("dsa.cpp.raw-command-exec", rule_ids)
        self.assertIn("dsa.cpp.unsafe-string-copy", rule_ids)
        self.assertIn("dsa.cpp.sql-concat", rule_ids)
        self.assertIn("dsa.cpp.raw-new-delete", rule_ids)

    def test_detects_java_siebel_mvp_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            source = target / "IntegrationHandler.java"
            source.write_text(
                "\n".join(
                    [
                        "import java.io.*;",
                        "import javax.xml.parsers.DocumentBuilderFactory;",
                        "class IntegrationHandler {",
                        "  void handle(InputStream input, Connection connection, String id, HttpServletRequest request) throws Exception {",
                        "    new ObjectInputStream(input).readObject();",
                        '    Runtime.getRuntime().exec("run-report " + request.getParameter("name"));',
                        '    connection.createStatement().executeQuery("select * from S_ORG_EXT where ROW_ID = " + id);',
                        '    File file = new File("/siebel/attachments/" + request.getParameter("file"));',
                        "    DocumentBuilderFactory.newInstance();",
                        "  }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            result = scan_target(target, include_semgrep=False, max_file_kb=512)

        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertIn("dsa.java.unsafe-deserialization", rule_ids)
        self.assertIn("dsa.java.runtime-exec", rule_ids)
        self.assertIn("dsa.java.sql-concat", rule_ids)
        self.assertIn("dsa.java.path-traversal-risk", rule_ids)
        self.assertIn("dsa.java.weak-xml-parser", rule_ids)

    def test_language_scoped_rules_do_not_cross_fire(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            source = target / "notes.txt"
            source.write_text("system(command)\nnew ObjectInputStream(input)\n", encoding="utf-8")

            result = scan_target(target, include_semgrep=False, max_file_kb=512)

        self.assertEqual(result.scanned_files, 0)
        self.assertEqual(result.findings, ())


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dsa.java_rest_verifier import verify_java_rest_target


class JavaRestVerifierTests(unittest.TestCase):
    def test_verifies_rest_input_to_command_sink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "RestController.java"
            source.write_text(
                "\n".join(
                    [
                        "class RestController {",
                        '  @GetMapping("/workspace/{owner}")',
                        '  public String run(@PathVariable("owner") String owner) throws Exception {',
                        '    String cmd = "tool --owner " + owner;',
                        "    Runtime.getRuntime().exec(cmd);",
                        '    return "ok";',
                        "  }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            result = verify_java_rest_target(Path(tmp))

        self.assertEqual(len(result.traces), 1)
        trace = result.traces[0]
        self.assertEqual(trace.status, "verified")
        self.assertEqual(trace.bug_class, "command-injection")
        self.assertEqual(trace.tainted_symbols, ("cmd",))

    def test_marks_guarded_file_path_as_probable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "RestController.java"
            source.write_text(
                "\n".join(
                    [
                        "class RestController {",
                        '  @GetMapping("/file/{name}")',
                        '  public String file(@PathVariable("name") String name) {',
                        '    if (!name.matches("[A-Za-z0-9_.-]+")) return "bad";',
                        '    File file = new File("/base/" + name);',
                        "    return file.getName();",
                        "  }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            result = verify_java_rest_target(Path(tmp))

        self.assertEqual(len(result.traces), 1)
        trace = result.traces[0]
        self.assertEqual(trace.status, "probable")
        self.assertEqual(trace.bug_class, "path-traversal")
        self.assertTrue(trace.guard_evidence)

    def test_does_not_report_non_rest_method(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "Worker.java"
            source.write_text(
                "\n".join(
                    [
                        "class Worker {",
                        "  public void run(String value) throws Exception {",
                        "    Runtime.getRuntime().exec(value);",
                        "  }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            result = verify_java_rest_target(Path(tmp))

        self.assertEqual(result.traces, ())


if __name__ == "__main__":
    unittest.main()


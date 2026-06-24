from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "sam_rest_command_injection_pocs.py"


def load_module():
    spec = importlib.util.spec_from_file_location("sam_rest_command_injection_pocs", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SamRestPocTests(unittest.TestCase):
    def test_builds_expected_cases(self) -> None:
        module = load_module()
        cases = {case.case_id: case for case in module.build_cases()}

        self.assertIn("workspace", cases)
        self.assertIn("clearcase", cases)
        self.assertIn("svn_old", cases)
        self.assertIn("svn_sam", cases)
        self.assertIn("orahubmerge-argument-injection", cases)

    def test_url_encodes_command_payloads(self) -> None:
        module = load_module()
        case = {case.case_id: case for case in module.build_cases()}["workspace"]
        url = module.build_url("http://localhost:8080/bugdb", case)

        self.assertIn("workspace/owner/", url)
        self.assertIn("%26", url)
        self.assertNotIn(" & ", url)

    def test_execute_requires_authorization_flag(self) -> None:
        module = load_module()

        result = module.main(["--execute"])

        self.assertEqual(result, 2)


if __name__ == "__main__":
    unittest.main()

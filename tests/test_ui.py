from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dsa.ui import JobStore, _handler_factory

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class UiServerTests(unittest.TestCase):
    def test_ui_scan_job_generates_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "sample_repo"
            target.mkdir()
            (target / "app.py").write_text(
                "import subprocess\nsubprocess.run(value, shell=True)\n",
                encoding="utf-8",
            )
            output = root / "reports"
            output.mkdir()
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                _handler_factory(JobStore(), output),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                scanners = _get_json(f"{base}/api/scanners")
                self.assertIn("semgrep", scanners["supported"])

                request = urllib.request.Request(
                    f"{base}/api/scan",
                    data=json.dumps({"target": str(target)}).encode("utf-8"),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                with OPENER.open(request, timeout=5) as response:
                    job = json.loads(response.read().decode("utf-8"))

                job_id = job["job_id"]
                for _ in range(30):
                    job = _get_json(f"{base}/api/jobs/{job_id}")
                    if job["status"] in {"succeeded", "failed"}:
                        break
                    time.sleep(0.1)

                self.assertEqual(job["status"], "succeeded")
                self.assertEqual(job["summary"]["findings"], 1)
                report = OPENER.open(
                    f"{base}/api/files/{job_id}/report",
                    timeout=5,
                ).read().decode("utf-8")
                self.assertIn("Shell command execution with shell=True", report)
            finally:
                server.shutdown()
                server.server_close()


def _get_json(url: str) -> dict:
    with OPENER.open(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()

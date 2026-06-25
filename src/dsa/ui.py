from __future__ import annotations

import html
import json
import threading
import time
import traceback
import uuid
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .artifacts import (
    scan_result_to_artifact,
    verification_result_to_artifact,
    write_artifact,
)
from .external_scanners import SUPPORTED_SCANNERS, available_scanners
from .java_rest_verifier import verify_java_rest_target
from .report import render_markdown
from .scanner import scan_target
from .triage_report import render_verification_markdown
from .validation import validate_artifact, write_validation_json
from .validation_report import render_validation_markdown


@dataclass
class UiJob:
    job_id: str
    kind: str
    status: str = "queued"
    message: str = "Queued"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    report_path: Path | None = None
    json_path: Path | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    traceback: str = ""


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, UiJob] = {}
        self._lock = threading.Lock()

    def create(self, kind: str, runner: Callable[[UiJob], None]) -> UiJob:
        job = UiJob(job_id=uuid.uuid4().hex[:12], kind=kind)
        with self._lock:
            self._jobs[job.job_id] = job
        thread = threading.Thread(target=self._run, args=(job.job_id, runner), daemon=True)
        thread.start()
        return job

    def get(self, job_id: str) -> UiJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **updates: Any) -> None:
        with self._lock:
            job = self._jobs[job_id]
            for key, value in updates.items():
                setattr(job, key, value)

    def _run(self, job_id: str, runner: Callable[[UiJob], None]) -> None:
        job = self.get(job_id)
        if job is None:
            return
        self.update(
            job_id,
            status="running",
            message="Running",
            started_at=time.time(),
        )
        try:
            runner(job)
            self.update(
                job_id,
                status="succeeded",
                message="Completed",
                finished_at=time.time(),
            )
        except Exception as exc:
            self.update(
                job_id,
                status="failed",
                message="Failed",
                error=str(exc),
                traceback=traceback.format_exc(),
                finished_at=time.time(),
            )


def serve_ui(
    host: str = "127.0.0.1",
    port: int = 8765,
    output_dir: Path | None = None,
    open_browser: bool = False,
) -> None:
    output_root = (output_dir or (Path.cwd() / "dsa-ui-output")).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    store = JobStore()
    handler = _handler_factory(store, output_root)
    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{server.server_port}"
    print(f"Defensive Security Agent UI: {url}")
    print(f"Reports directory: {output_root}")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Defensive Security Agent UI")
    finally:
        server.server_close()


def _handler_factory(store: JobStore, output_root: Path) -> type[BaseHTTPRequestHandler]:
    class UiHandler(BaseHTTPRequestHandler):
        server_version = "DSAUI/0.1"

        def do_GET(self) -> None:
            if self.path == "/" or self.path.startswith("/?"):
                self._send_html(INDEX_HTML)
                return
            if self.path == "/api/scanners":
                installed = set(available_scanners())
                self._send_json(
                    {
                        "supported": sorted(SUPPORTED_SCANNERS),
                        "installed": sorted(installed),
                    }
                )
                return
            if self.path.startswith("/api/jobs/"):
                job_id = self.path.rsplit("/", 1)[-1]
                job = store.get(job_id)
                if job is None:
                    self._send_json({"error": "job not found"}, HTTPStatus.NOT_FOUND)
                    return
                self._send_json(_job_payload(job))
                return
            if self.path.startswith("/api/files/"):
                parts = self.path.split("/")
                if len(parts) != 5:
                    self._send_json({"error": "invalid file request"}, HTTPStatus.BAD_REQUEST)
                    return
                _, _, _, job_id, kind = parts
                job = store.get(job_id)
                if job is None:
                    self._send_json({"error": "job not found"}, HTTPStatus.NOT_FOUND)
                    return
                path = job.report_path if kind == "report" else job.json_path if kind == "json" else None
                if path is None or not path.exists():
                    self._send_json({"error": "file not found"}, HTTPStatus.NOT_FOUND)
                    return
                self._send_text(path.read_text(encoding="utf-8", errors="replace"))
                return
            self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            if self.path == "/api/scan":
                payload = self._read_json()
                job = store.create("scan", lambda item: _run_scan_job(item, payload, output_root))
                self._send_json(_job_payload(job), HTTPStatus.ACCEPTED)
                return
            if self.path == "/api/triage":
                payload = self._read_json()
                job = store.create("triage", lambda item: _run_triage_job(item, payload, output_root))
                self._send_json(_job_payload(job), HTTPStatus.ACCEPTED)
                return
            if self.path == "/api/validate":
                payload = self._read_json()
                job = store.create(
                    "validate",
                    lambda item: _run_validation_job(item, payload, output_root),
                )
                self._send_json(_job_payload(job), HTTPStatus.ACCEPTED)
                return
            self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("content-length", "0") or "0")
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            payload = json.loads(raw or "{}")
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            return payload

        def _send_html(self, body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_text(self, body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("content-type", "text/plain; charset=utf-8")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
            data = json.dumps(payload, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return UiHandler


def _run_scan_job(job: UiJob, payload: dict[str, Any], output_root: Path) -> None:
    target = _required_path(payload, "target")
    prefix = _output_prefix("scan", target)
    report_path = output_root / f"{prefix}.md"
    json_path = output_root / f"{prefix}.json"
    external_scanners = tuple(str(item) for item in payload.get("external_scanners", []) if str(item))
    include_all = bool(payload.get("include_all_external_scanners"))
    if include_all:
        external_scanners = tuple(sorted(SUPPORTED_SCANNERS))
    result = scan_target(
        target=target,
        include_semgrep=False,
        max_file_kb=int(payload.get("max_file_kb") or 512),
        external_scanners=external_scanners,
    )
    report_path.write_text(render_markdown(result), encoding="utf-8")
    write_artifact(json_path, scan_result_to_artifact(result))
    job.report_path = report_path
    job.json_path = json_path
    job.summary = {
        "target": str(target),
        "scanned_files": result.scanned_files,
        "skipped_files": result.skipped_files,
        "findings": len(result.findings),
        "external_scanners": list(external_scanners),
    }


def _run_triage_job(job: UiJob, payload: dict[str, Any], output_root: Path) -> None:
    target = _required_path(payload, "target")
    prefix = _output_prefix("triage", target)
    report_path = output_root / f"{prefix}.md"
    json_path = output_root / f"{prefix}.json"
    result = verify_java_rest_target(
        target=target,
        max_file_kb=int(payload.get("max_file_kb") or 512),
    )
    report_path.write_text(render_verification_markdown(result), encoding="utf-8")
    write_artifact(json_path, verification_result_to_artifact(result))
    job.report_path = report_path
    job.json_path = json_path
    job.summary = {
        "target": str(target),
        "scanned_files": result.scanned_files,
        "traces": len(result.traces),
    }


def _run_validation_job(job: UiJob, payload: dict[str, Any], output_root: Path) -> None:
    findings = _required_path(payload, "findings")
    base_url = str(payload.get("base_url") or "").strip()
    if not base_url:
        raise ValueError("base_url is required")
    if bool(payload.get("execute")) and not bool(payload.get("i_understand_authorized_test")):
        raise ValueError("execution requires Authorized sandbox acknowledgement")
    profile = str(payload.get("profile") or "generic")
    prefix = _output_prefix("validate", findings)
    report_path = output_root / f"{prefix}.md"
    json_path = output_root / f"{prefix}.json"
    probe_spec = str(payload.get("probe_spec") or "").strip()
    allow_hosts = tuple(
        item.strip()
        for item in str(payload.get("allow_hosts") or "").replace(",", "\n").splitlines()
        if item.strip()
    )
    result = validate_artifact(
        artifact_path=findings,
        base_url=base_url,
        profile=profile,  # type: ignore[arg-type]
        execute=bool(payload.get("execute")),
        allow_hosts=allow_hosts,
        timeout=int(payload.get("timeout") or 20),
        probe_spec_path=Path(probe_spec).expanduser().resolve() if probe_spec else None,
        aggressive_sandbox=bool(payload.get("aggressive_sandbox")),
        max_mutations_per_case=int(payload.get("max_mutations_per_case") or 25),
    )
    report_path.write_text(render_validation_markdown(result), encoding="utf-8")
    write_validation_json(json_path, result)
    job.report_path = report_path
    job.json_path = json_path
    job.summary = {
        "findings": str(findings),
        "base_url": base_url,
        "profile": profile,
        "executed": result.executed,
        "cases": len(result.cases),
    }


def _required_path(payload: dict[str, Any], key: str) -> Path:
    raw = str(payload.get(key) or "").strip()
    if not raw:
        raise ValueError(f"{key} is required")
    path = Path(raw).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"{key} does not exist: {path}")
    return path


def _output_prefix(kind: str, source: Path) -> str:
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    return f"{kind}-{_slug(source.stem or source.name)}-{timestamp}"


def _slug(value: str) -> str:
    cleaned = []
    for char in value.lower():
        if char.isalnum():
            cleaned.append(char)
        elif char in {"-", "_", "."}:
            cleaned.append("-")
    text = "".join(cleaned).strip("-")
    while "--" in text:
        text = text.replace("--", "-")
    return text or "target"


def _job_payload(job: UiJob) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "kind": job.kind,
        "status": job.status,
        "message": job.message,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "report_path": str(job.report_path) if job.report_path else "",
        "json_path": str(job.json_path) if job.json_path else "",
        "summary": job.summary,
        "error": job.error,
        "traceback": job.traceback,
    }


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Defensive Security Agent</title>
  <style>
    :root {
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1f2933;
      --muted: #5d6975;
      --line: #d9dee5;
      --accent: #0f6b68;
      --accent-2: #8a5a12;
      --danger: #a43c32;
      --ok: #246b42;
      --shadow: 0 1px 3px rgba(24, 39, 57, 0.12);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
      font-size: 14px;
      letter-spacing: 0;
    }
    header {
      height: 58px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 24px;
      background: #ffffff;
      border-bottom: 1px solid var(--line);
    }
    h1 { font-size: 18px; margin: 0; font-weight: 650; }
    main {
      display: grid;
      grid-template-columns: 280px minmax(0, 1fr);
      min-height: calc(100vh - 58px);
    }
    nav {
      border-right: 1px solid var(--line);
      background: #eef1f4;
      padding: 16px;
    }
    .tab {
      width: 100%;
      min-height: 42px;
      border: 1px solid transparent;
      background: transparent;
      color: var(--text);
      text-align: left;
      padding: 10px 12px;
      margin-bottom: 6px;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
    }
    .tab.active { background: #ffffff; border-color: var(--line); box-shadow: var(--shadow); }
    .workspace { padding: 20px; }
    section { display: none; }
    section.active { display: block; }
    .grid {
      display: grid;
      grid-template-columns: minmax(360px, 520px) minmax(360px, 1fr);
      gap: 16px;
      align-items: start;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 16px;
    }
    h2 { font-size: 16px; margin: 0 0 14px; }
    label { display: block; font-weight: 600; margin: 12px 0 6px; }
    input, select, textarea {
      width: 100%;
      min-height: 38px;
      border: 1px solid #bfc8d2;
      border-radius: 6px;
      padding: 8px 10px;
      font: inherit;
      background: #ffffff;
      color: var(--text);
    }
    textarea { min-height: 78px; resize: vertical; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .checks {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 6px 10px;
      margin-top: 6px;
    }
    .check {
      display: flex;
      align-items: center;
      gap: 8px;
      min-height: 30px;
      font-weight: 500;
      color: var(--text);
    }
    .check input { width: 16px; min-height: 16px; }
    button.primary {
      min-height: 40px;
      border: 0;
      background: var(--accent);
      color: #ffffff;
      border-radius: 6px;
      padding: 0 14px;
      font-weight: 700;
      cursor: pointer;
      margin-top: 16px;
    }
    button.secondary {
      min-height: 34px;
      border: 1px solid var(--line);
      background: #ffffff;
      color: var(--text);
      border-radius: 6px;
      padding: 0 10px;
      font-weight: 650;
      cursor: pointer;
      margin-right: 8px;
    }
    .status {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fbfcfd;
      margin-bottom: 10px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      padding: 2px 8px;
      border-radius: 999px;
      background: #e7edf3;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }
    .badge.succeeded { background: #dff1e6; color: var(--ok); }
    .badge.failed { background: #f6dfdc; color: var(--danger); }
    .badge.running { background: #f4ead6; color: var(--accent-2); }
    .paths {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      line-height: 1.5;
      color: var(--muted);
      overflow-wrap: anywhere;
    }
    pre {
      min-height: 420px;
      max-height: 70vh;
      overflow: auto;
      background: #111827;
      color: #e5edf7;
      padding: 14px;
      border-radius: 8px;
      font-size: 12px;
      line-height: 1.45;
      white-space: pre-wrap;
      margin: 0;
    }
    .muted { color: var(--muted); }
    .top-actions { display: flex; align-items: center; gap: 8px; }
    @media (max-width: 980px) {
      main { grid-template-columns: 1fr; }
      nav { border-right: 0; border-bottom: 1px solid var(--line); display: flex; gap: 8px; overflow-x: auto; }
      .tab { min-width: 140px; }
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Defensive Security Agent</h1>
    <div class="top-actions"><span class="badge" id="scannerCount">Scanners</span></div>
  </header>
  <main>
    <nav>
      <button class="tab active" data-tab="scan">Scan</button>
      <button class="tab" data-tab="triage">Java REST Triage</button>
      <button class="tab" data-tab="validate">Validate</button>
    </nav>
    <div class="workspace">
      <section id="scan" class="active">
        <div class="grid">
          <div class="panel">
            <h2>Scan Repository</h2>
            <form id="scanForm">
              <label for="scanTarget">Repository or folder path</label>
              <input id="scanTarget" name="target" placeholder="/Users/johnm/codex_general/my_projects/siebel-monorepo" required>
              <div class="row">
                <div>
                  <label for="scanMaxKb">Max file KB</label>
                  <input id="scanMaxKb" name="max_file_kb" type="number" min="1" value="512">
                </div>
                <div>
                  <label class="check" style="margin-top: 34px;">
                    <input id="scanAll" name="include_all_external_scanners" type="checkbox"> All installed scanners
                  </label>
                </div>
              </div>
              <label>External scanners</label>
              <div id="scannerChecks" class="checks"></div>
              <button class="primary" type="submit">Run Scan</button>
            </form>
          </div>
          <div class="panel"><h2>Job Output</h2><div id="scanStatus"></div><pre id="scanOutput">No scan job yet.</pre></div>
        </div>
      </section>

      <section id="triage">
        <div class="grid">
          <div class="panel">
            <h2>Java REST Triage</h2>
            <form id="triageForm">
              <label for="triageTarget">Java REST module path</label>
              <input id="triageTarget" name="target" required>
              <label for="triageMaxKb">Max file KB</label>
              <input id="triageMaxKb" name="max_file_kb" type="number" min="1" value="512">
              <button class="primary" type="submit">Run Triage</button>
            </form>
          </div>
          <div class="panel"><h2>Job Output</h2><div id="triageStatus"></div><pre id="triageOutput">No triage job yet.</pre></div>
        </div>
      </section>

      <section id="validate">
        <div class="grid">
          <div class="panel">
            <h2>Validate Findings</h2>
            <form id="validateForm">
              <label for="findings">Findings JSON path</label>
              <input id="findings" name="findings" required>
              <label for="baseUrl">Sandbox base URL</label>
              <input id="baseUrl" name="base_url" placeholder="https://SIEBEL-SANDBOX-HOST" required>
              <div class="row">
                <div>
                  <label for="profile">Profile</label>
                  <select id="profile" name="profile">
                    <option value="generic">generic</option>
                    <option value="siebel-sam-rest">siebel-sam-rest</option>
                    <option value="http-probe">http-probe</option>
                  </select>
                </div>
                <div>
                  <label for="timeout">Timeout seconds</label>
                  <input id="timeout" name="timeout" type="number" min="1" value="20">
                </div>
              </div>
              <label for="probeSpec">Probe spec path</label>
              <input id="probeSpec" name="probe_spec" placeholder="examples/probe_specs/http-probe-template.json">
              <label for="allowHosts">Allow hosts</label>
              <textarea id="allowHosts" name="allow_hosts" placeholder="SIEBEL-SANDBOX-HOST"></textarea>
              <div class="checks">
                <label class="check"><input name="execute" type="checkbox"> Execute</label>
                <label class="check"><input name="i_understand_authorized_test" type="checkbox"> Authorized sandbox</label>
                <label class="check"><input name="aggressive_sandbox" type="checkbox"> Aggressive sandbox</label>
                <label class="check">Max mutations <input name="max_mutations_per_case" type="number" min="1" value="25"></label>
              </div>
              <button class="primary" type="submit">Run Validation</button>
            </form>
          </div>
          <div class="panel"><h2>Job Output</h2><div id="validateStatus"></div><pre id="validateOutput">No validation job yet.</pre></div>
        </div>
      </section>
    </div>
  </main>
  <script>
    const jobs = new Map();
    const outputs = {
      scan: document.getElementById('scanOutput'),
      triage: document.getElementById('triageOutput'),
      validate: document.getElementById('validateOutput')
    };
    const statuses = {
      scan: document.getElementById('scanStatus'),
      triage: document.getElementById('triageStatus'),
      validate: document.getElementById('validateStatus')
    };
    document.querySelectorAll('.tab').forEach(button => {
      button.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(item => item.classList.remove('active'));
        document.querySelectorAll('section').forEach(item => item.classList.remove('active'));
        button.classList.add('active');
        document.getElementById(button.dataset.tab).classList.add('active');
      });
    });

    async function initScanners() {
      const response = await fetch('/api/scanners');
      const payload = await response.json();
      document.getElementById('scannerCount').textContent = `${payload.installed.length}/${payload.supported.length} scanners installed`;
      const holder = document.getElementById('scannerChecks');
      holder.innerHTML = '';
      payload.supported.forEach(name => {
        const label = document.createElement('label');
        label.className = 'check';
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.name = 'external_scanners';
        input.value = name;
        label.appendChild(input);
        label.appendChild(document.createTextNode(`${name}${payload.installed.includes(name) ? '' : ' (missing)'}`));
        holder.appendChild(label);
      });
    }

    function formValues(form) {
      const data = new FormData(form);
      const payload = {};
      for (const [key, value] of data.entries()) {
        if (key === 'external_scanners') continue;
        payload[key] = value;
      }
      payload.external_scanners = data.getAll('external_scanners');
      form.querySelectorAll('input[type="checkbox"]').forEach(input => {
        if (input.name !== 'external_scanners') payload[input.name] = input.checked;
      });
      return payload;
    }

    async function submitJob(kind, endpoint, form) {
      outputs[kind].textContent = 'Starting job...';
      statuses[kind].innerHTML = '';
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {'content-type': 'application/json'},
        body: JSON.stringify(formValues(form))
      });
      const payload = await response.json();
      if (!response.ok) {
        outputs[kind].textContent = payload.error || JSON.stringify(payload, null, 2);
        return;
      }
      jobs.set(payload.job_id, kind);
      pollJob(payload.job_id);
    }

    async function pollJob(jobId) {
      const response = await fetch(`/api/jobs/${jobId}`);
      const job = await response.json();
      const kind = jobs.get(jobId) || job.kind;
      renderJob(kind, job);
      if (job.status === 'queued' || job.status === 'running') {
        setTimeout(() => pollJob(jobId), 1200);
      }
    }

    async function renderJob(kind, job) {
      const badgeClass = job.status === 'succeeded' ? 'succeeded' : job.status === 'failed' ? 'failed' : 'running';
      statuses[kind].innerHTML = `
        <div class="status">
          <div><strong>${job.kind}</strong> <span class="badge ${badgeClass}">${job.status}</span></div>
          <div>
            ${job.report_path ? `<button class="secondary" onclick="loadFile('${job.job_id}', 'report', '${kind}')">Report</button>` : ''}
            ${job.json_path ? `<button class="secondary" onclick="loadFile('${job.job_id}', 'json', '${kind}')">JSON</button>` : ''}
          </div>
        </div>
        <div class="paths">${escapeHtml(job.report_path || '')}<br>${escapeHtml(job.json_path || '')}</div>`;
      if (job.status === 'failed') {
        outputs[kind].textContent = `${job.error}\n\n${job.traceback || ''}`;
      } else {
        outputs[kind].textContent = JSON.stringify(job.summary || {}, null, 2);
      }
      if (job.status === 'succeeded' && job.report_path) {
        loadFile(job.job_id, 'report', kind);
      }
    }

    async function loadFile(jobId, fileKind, panelKind) {
      const response = await fetch(`/api/files/${jobId}/${fileKind}`);
      outputs[panelKind].textContent = await response.text();
    }

    function escapeHtml(value) {
      return String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
    }

    document.getElementById('scanForm').addEventListener('submit', event => {
      event.preventDefault();
      submitJob('scan', '/api/scan', event.currentTarget);
    });
    document.getElementById('triageForm').addEventListener('submit', event => {
      event.preventDefault();
      submitJob('triage', '/api/triage', event.currentTarget);
    });
    document.getElementById('validateForm').addEventListener('submit', event => {
      event.preventDefault();
      submitJob('validate', '/api/validate', event.currentTarget);
    });
    initScanners();
  </script>
</body>
</html>
"""

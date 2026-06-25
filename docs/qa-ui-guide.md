# QA Browser UI Guide

This guide is for QA engineers who prefer a browser screen instead of command
line options.

The UI runs locally on your machine. It does not require a shared server.

## Start The UI

From the project directory:

```bash
cd /Users/johnm/codex_general/my_projects/defensive-security-agent
python3 -m pip install -e .
dsa ui
```

Open this URL in a browser:

```text
http://127.0.0.1:8765
```

If port `8765` is already in use:

```bash
dsa ui --port 8770
```

Reports are written to:

```text
dsa-ui-output
```

To choose a different report folder:

```bash
dsa ui --output-dir /path/to/security-reports
```

## Scan A Repository

Use the **Scan** tab.

Fill in:

- repository or folder path
- max file size in KB
- optional external scanners

For the Siebel monorepo, use:

```text
/Users/johnm/codex_general/my_projects/siebel-monorepo
```

Click **Run Scan**.

When the job completes, the UI shows:

- job status
- report path
- JSON artifact path
- Markdown report content

Use the Markdown report for human review. Use the JSON artifact for validation.

## External Scanners

The Scan tab lists supported scanners and marks missing tools.

Common scanner choices:

- `semgrep`
- `gitleaks`
- `osv-scanner`
- `grype`
- `checkov`

The full install guide is:

```text
docs/scanner-tools.md
```

## Run Java REST Triage

Use the **Java REST Triage** tab.

Fill in:

- Java REST module path
- max file size in KB

Click **Run Triage**.

The output includes source-to-sink traces for Java REST-controlled input reaching
security-sensitive sinks.

Use the JSON artifact from this step when validating Java REST issues.

## Validate Findings

Use the **Validate** tab.

Fill in:

- findings JSON path
- sandbox base URL
- profile
- optional probe spec path
- allow hosts, if executing validation

Profiles:

- `generic`: creates validation steps for any findings JSON
- `siebel-sam-rest`: validates mapped SAM REST findings
- `http-probe`: runs reviewed HTTP probe specs

Start with dry-run validation. Leave **Execute** unchecked.

Click **Run Validation**.

Review the generated validation plan before running live sandbox requests.

## Execute Against A Sandbox

Use execution only for a DevOps-owned security sandbox.

Before executing:

- confirm the sandbox URL
- confirm the allow host value
- confirm the test account and data set
- confirm DevOps monitoring is active

In the UI:

1. Check **Execute**.
2. Check **Authorized sandbox**.
3. Enter the host in **Allow hosts**.
4. Click **Run Validation**.

The host in **Allow hosts** must match the host in the sandbox URL.

Example:

```text
Sandbox base URL: https://siebel-sandbox.example.com
Allow hosts:      siebel-sandbox.example.com
```

## Aggressive Sandbox Mode

Use **Aggressive sandbox** only with the `http-probe` profile and a reviewed
probe spec.

This mode expands probe specs into multiple payload variants.

It is useful for:

- SQL input handling checks
- reflected content checks
- path traversal canary checks
- command-injection marker checks
- XML parser marker checks

The UI still writes a report with:

- request sent
- expected result
- actual response preview
- manual verification notes
- bug filing recommendation

## How To Decide Whether To File A Bug

File a bug when the report and human review show clear evidence, such as:

- unauthorized data was returned
- stack traces or framework internals were exposed
- SQL or parser errors were exposed
- a marker value appeared where it should not
- a server log confirms a risky execution path

Do not file as reproduced when:

- the job only produced a dry-run plan
- the request did not reach the sandbox
- the result is inconclusive
- the endpoint or data set was not approved for testing

## Common Problems

### The browser page does not open

Check that the UI is running:

```text
Defensive Security Agent UI: http://127.0.0.1:8765
```

Then open the URL manually.

### A scanner says missing

Install that scanner or leave it unchecked. Built-in rules still run.

### Validation fails with host allowlist error

Make sure **Allow hosts** contains only the hostname, not the full URL.

Correct:

```text
siebel-sandbox.example.com
```

Incorrect:

```text
https://siebel-sandbox.example.com
```

### No probe cases matched

The probe spec did not match the findings JSON. Check the probe spec fields:

- `rule_ids`
- `categories`
- `tags_any`
- `path_contains`
- `lines`

## Stop The UI

Return to the terminal running `dsa ui` and press:

```text
Ctrl-C
```

# Defensive Security Agent Beginner Guide

This guide explains what the Defensive Security Agent is, what it does, and how
to use it from a clean checkout.

You do not need to know the internals of the tool to follow this guide. The
commands assume you are running from the project directory:

```bash
cd /Users/johnm/codex_general/my_projects/defensive-security-agent
```

## What This Tool Is

Defensive Security Agent, or `dsa`, is a command-line tool for authorized
security review of source code and controlled test deployments.

It has two main jobs:

1. **Scan a local code repository.**
   It reads source files, looks for risky security patterns, and writes a report
   with possible vulnerabilities.

2. **Validate findings against an authorized sandbox deployment.**
   It takes the scan output, builds validation steps, and can run reviewed HTTP
   probes against a DevOps-owned test deployment.

The tool is useful when you want to answer questions such as:

- Where does the Siebel codebase appear to have security risk?
- Which findings are high priority?
- What exact file and line created the suspicion?
- How can a human reviewer reproduce or validate the issue?
- If the sandbox deployment is vulnerable, what evidence should be included in a
  bug?

## What This Tool Is Not

This tool is not meant to attack random systems.

Use it only for systems you own or are explicitly authorized to test. Live
validation requires a controlled target, explicit command flags, and target host
allowlisting.

The tool is designed to avoid credential theft, persistence, exfiltration of
real data, and irreversible destructive behavior. Aggressive sandbox mode means
broader payload coverage in a controlled environment, not uncontrolled attack
automation.

## Key Terms

**Repository**
: A folder containing source code, for example the Siebel monorepo.

**Finding**
: A possible security issue found by the scanner.

**Artifact**
: A JSON file produced by the scanner or triage command. It is used as input to
the validation step.

**Triage**
: A deeper check that tries to verify a source-to-sink path, such as REST input
reaching command execution.

**Validation**
: A plan or test run that checks whether a finding appears reachable in a
deployed sandbox.

**Probe spec**
: A JSON file that defines which sandbox endpoints to test, which fields to
mutate, what payload sets to use, and what evidence should count as suspicious.

**Aggressive sandbox mode**
: A mode that expands reviewed probe specs into multiple payload variants. This
is intended for a dedicated DevOps security sandbox.

## Install The Tool

From the project directory:

```bash
python3 -m pip install -e .
```

This installs the `dsa` command in editable mode. Editable mode means changes to
the local source code are picked up without reinstalling.

If you do not want to install it, you can run it with:

```bash
PYTHONPATH=src python3 -m dsa --help
```

## Check That It Works

Run:

```bash
dsa --help
```

You should see commands such as:

- `scan`
- `triage`
- `validate`

If `dsa` is not found, use:

```bash
PYTHONPATH=src python3 -m dsa --help
```

## Use The Browser UI

QA engineers can use the local browser UI instead of typing scan and validation
commands.

Start it with:

```bash
dsa ui
```

Then open:

```text
http://127.0.0.1:8765
```

The UI guide is here:

```bash
docs/qa-ui-guide.md
```

## Part 1: Scan A Repository

Use `scan` to inspect a local source tree.

Example for the Siebel monorepo:

```bash
dsa scan \
  --target /Users/johnm/codex_general/my_projects/siebel-monorepo \
  --output siebel-monorepo-security-report.md \
  --json-output siebel-monorepo-security-findings.json
```

This produces two files:

- `siebel-monorepo-security-report.md`
- `siebel-monorepo-security-findings.json`

The Markdown report is for humans. Open it in your editor and review the
findings.

The JSON file is for the next step. Do not edit it unless you know what you are
doing.

## Recommended Optional Scanner Setup

DSA has built-in rules, so the basic scan works immediately. For stronger
coverage, install optional free/open-source scanners such as Semgrep, Gitleaks,
OSV-Scanner, Grype, Bandit, Checkov, and others.

The full prerequisite and install guide is here:

```bash
docs/scanner-tools.md
```

After installing optional tools, run selected scanners like this:

```bash
dsa scan \
  --target /Users/johnm/codex_general/my_projects/siebel-monorepo \
  --external-scanner semgrep \
  --external-scanner gitleaks \
  --external-scanner osv-scanner \
  --output siebel-security-report.md \
  --json-output siebel-security-findings.json
```

To run every supported external scanner that is installed:

```bash
dsa scan \
  --target /Users/johnm/codex_general/my_projects/siebel-monorepo \
  --include-all-external-scanners \
  --output siebel-all-tools-report.md \
  --json-output siebel-all-tools-findings.json
```

## What The Scan Report Contains

Each finding includes:

- severity
- rule ID
- source file and line
- code evidence
- why it matters
- recommended remediation
- tags such as `injection`, `database`, `java`, `cpp`, or `xml`

Example finding categories include:

- unsafe C/C++ string handling
- C/C++ command execution
- C++ SQL string construction
- Java command execution
- Java SQL string construction
- Java native deserialization
- Java path traversal risk
- weak XML parser hardening
- hard-coded secrets
- debug mode exposure

## Optional: Include Semgrep

If Semgrep is installed, you can include it:

```bash
dsa scan \
  --target /Users/johnm/codex_general/my_projects/siebel-monorepo \
  --include-semgrep \
  --output siebel-monorepo-security-report.md \
  --json-output siebel-monorepo-security-findings.json
```

If Semgrep is not installed, leave off `--include-semgrep`.

## Part 1B: Triage Java REST Source-To-Sink Findings

Use `triage` when you want deeper evidence for Java REST code.

Example:

```bash
dsa triage \
  --kind java-rest \
  --target /path/to/java/rest/module \
  --output java-rest-verification-report.md \
  --json-output java-rest-verification-findings.json
```

This checks whether REST-controlled input appears to reach dangerous sinks such
as:

- command execution
- file path construction
- SQL execution
- Java native deserialization
- XML parsing

The triage report marks traces as:

- `verified`: request-controlled data reaches a sink and no simple guard was
  seen
- `probable`: request-controlled data reaches a sink, but guard evidence needs
  human review

## Part 2: Create A Validation Plan

Validation consumes the JSON file from `scan` or `triage`.

Start with a dry run. A dry run does not contact the sandbox. It only creates a
plan.

```bash
dsa validate \
  --findings siebel-monorepo-security-findings.json \
  --base-url https://SIEBEL-SANDBOX-HOST \
  --profile generic \
  --output siebel-validation-plan.md \
  --json-output siebel-validation-plan.json
```

The generic profile creates manual validation steps for each finding. Use this
when no product-specific validation profile exists yet.

## Use A Siebel SAM REST Validation Profile

For known SAM REST command-injection findings, use:

```bash
dsa validate \
  --findings java-rest-verification-findings.json \
  --base-url http://SIEBEL-SANDBOX-HOST:PORT/bugdb \
  --profile siebel-sam-rest \
  --output sam-rest-validation-plan.md
```

To execute the safe validation requests:

```bash
dsa validate \
  --findings java-rest-verification-findings.json \
  --base-url http://SIEBEL-SANDBOX-HOST:PORT/bugdb \
  --profile siebel-sam-rest \
  --execute \
  --i-understand-authorized-test \
  --allow-host SIEBEL-SANDBOX-HOST \
  --output sam-rest-validation-results.md
```

The host in `--allow-host` must match the host in `--base-url`.

## Use The Broader HTTP Probe Profile

Use `http-probe` for validation beyond SAM.

The profile needs a probe spec file. A starter template is here:

```bash
examples/probe_specs/http-probe-template.json
```

Dry run:

```bash
dsa validate \
  --findings siebel-monorepo-security-findings.json \
  --base-url https://SIEBEL-SANDBOX-HOST \
  --profile http-probe \
  --probe-spec examples/probe_specs/http-probe-template.json \
  --output siebel-http-probe-plan.md
```

Execute reviewed probes:

```bash
dsa validate \
  --findings siebel-monorepo-security-findings.json \
  --base-url https://SIEBEL-SANDBOX-HOST \
  --profile http-probe \
  --probe-spec examples/probe_specs/http-probe-template.json \
  --execute \
  --i-understand-authorized-test \
  --allow-host SIEBEL-SANDBOX-HOST \
  --output siebel-http-probe-results.md
```

## Use Aggressive Sandbox Mode

Aggressive sandbox mode expands reviewed probe specs into multiple payload
variants.

Use it only against a DevOps-owned security sandbox.

```bash
dsa validate \
  --findings siebel-monorepo-security-findings.json \
  --base-url https://SIEBEL-SANDBOX-HOST \
  --profile http-probe \
  --probe-spec examples/probe_specs/http-probe-template.json \
  --aggressive-sandbox \
  --max-mutations-per-case 25 \
  --execute \
  --i-understand-authorized-test \
  --allow-host SIEBEL-SANDBOX-HOST \
  --output siebel-http-probe-aggressive-results.md
```

Aggressive sandbox mode can mutate:

- query parameters
- JSON fields
- HTTP headers
- request body placeholders
- path placeholders

Built-in payload sets:

- `sqli-basic`
- `xss-reflection`
- `path-traversal-canary`
- `command-injection-marker`
- `xml-parser-marker`

## How To Read A Validation Report

Each validation case includes:

- source evidence from the scanner or triage artifact
- validation steps
- expected result
- actual response preview, if executed
- manual verification instruction
- bug filing recommendation

The bug filing recommendation usually says one of these:

- do not file yet because this is only a plan
- do not file because the request did not reach the sandbox
- file a bug if the reviewer confirms the expected indicator or server-side
  evidence

The tool does not replace the human reviewer. The reviewer decides whether the
evidence is strong enough to file a bug.

## How To Edit A Probe Spec

A probe spec is a JSON file. Each case has:

- `case_id`: unique name for the case
- `title`: human-readable title
- `category`: issue category
- `match`: which scanner findings this probe applies to
- `request`: HTTP request to send
- `mutations`: optional payload expansion rules
- `expected`: response indicators to look for
- `manual_verification`: what the reviewer should check
- `notes`: extra context

Simple example:

```json
{
  "profile": "dsa.http-probe.v1",
  "cases": [
    {
      "case_id": "input.injection-sweep",
      "title": "Input handling injection sweep",
      "category": "input-validation",
      "match": {
        "tags_any": ["injection", "database"]
      },
      "request": {
        "method": "GET",
        "path": "/sandbox/search",
        "query": {
          "q": "DSA_BASELINE"
        }
      },
      "mutations": [
        {
          "location": "query",
          "name": "q",
          "payload_set": "sqli-basic"
        }
      ],
      "expected": {
        "status_codes": [200, 400, 500],
        "body_contains_any": ["SQL", "syntax", "Exception"]
      },
      "manual_verification": "Compare baseline and mutated responses. File a bug if SQL or framework internals are exposed."
    }
  ]
}
```

## Recommended Workflow For A New User

1. Install the tool.
2. Run a scan on a small sample folder.
3. Open the Markdown report and understand the fields.
4. Run a scan on the full Siebel monorepo.
5. Run `validate --profile generic` to create an initial validation plan.
6. Add or edit an HTTP probe spec for known sandbox endpoints.
7. Run `validate --profile http-probe` in dry-run mode.
8. Review the generated requests with DevOps/security.
9. Run with `--execute` only after the sandbox host and data set are approved.
10. Use `--aggressive-sandbox` only for the dedicated security sandbox.
11. File bugs only when the report plus human verification show clear evidence.

## Common Errors

### `dsa: command not found`

Install the package:

```bash
python3 -m pip install -e .
```

Or run with:

```bash
PYTHONPATH=src python3 -m dsa --help
```

### `--execute requires --i-understand-authorized-test`

This is expected. Live validation needs explicit confirmation:

```bash
--execute --i-understand-authorized-test
```

### `target host is not in --allow-host`

The hostname in `--base-url` must appear in `--allow-host`.

Example:

```bash
--base-url https://siebel-sandbox.example.com \
--allow-host siebel-sandbox.example.com
```

### No HTTP probe cases matched

The probe spec did not match the scanner artifact. Check:

- `rule_ids`
- `categories`
- `tags_any`
- `path_contains`
- `lines`

Also confirm you used the correct findings JSON file.

## What To Give A Bug Reviewer

For a reproduced issue, include:

- validation report section for the case
- source file and line
- request command generated by the tool
- expected result
- actual result
- server logs or audit evidence
- sandbox user and data set used
- recommended remediation from the scan report

## Quick Command Cheat Sheet

Scan:

```bash
dsa scan --target /path/to/repo --output report.md --json-output findings.json
```

Triage Java REST:

```bash
dsa triage --kind java-rest --target /path/to/java --output triage.md --json-output triage.json
```

Create validation plan:

```bash
dsa validate --findings findings.json --base-url https://sandbox --profile generic --output validation.md
```

Run HTTP probes:

```bash
dsa validate --findings findings.json --base-url https://sandbox --profile http-probe --probe-spec probes.json --execute --i-understand-authorized-test --allow-host sandbox --output results.md
```

Run aggressive sandbox mutations:

```bash
dsa validate --findings findings.json --base-url https://sandbox --profile http-probe --probe-spec probes.json --aggressive-sandbox --max-mutations-per-case 25 --execute --i-understand-authorized-test --allow-host sandbox --output aggressive-results.md
```

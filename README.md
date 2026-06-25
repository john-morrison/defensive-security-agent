# Defensive Security Agent

A defensive code-security agent scaffold for internal repositories and authorized
deployment validation.

New to this tool? Start with the beginner walkthrough:

```bash
docs/beginner-guide.md
```

To install optional scanners and understand how to run them:

```bash
docs/scanner-tools.md
```

The project is organized around the two-part workflow:

1. **Repository scanner**: scan a local Siebel or general-purpose repository and
   produce evidence-backed findings.
2. **Validation agent**: consume the scanner or triage artifact, build
   human-reproducible validation steps, and optionally run non-destructive probes
   against an explicitly authorized test deployment.

The implementation remains intentionally conservative:

- reads local source trees only during scanning
- runs heuristic risk checks and optional external scanners when present
- writes Markdown reports and machine-readable JSON artifacts
- makes deployment validation dry-run by default
- requires authorization acknowledgement and target host allowlisting before any
  live validation request is sent
- avoids credential theft, data exfiltration, persistence, and destructive payloads
- supports broad sandbox validation through reviewed probe specs rather than
  unconstrained payload generation

## Quick Start

Install the local CLI in editable mode:

```bash
python3 -m pip install -e .
```

```bash
dsa scan --target /path/to/repo --output security-report.md
```

Write the Part 1 machine-readable artifact:

```bash
dsa scan \
  --target /path/to/repo \
  --output security-report.md \
  --json-output security-findings.json
```

Run selected external scanners when installed:

```bash
dsa scan \
  --target /path/to/repo \
  --external-scanner semgrep \
  --external-scanner gitleaks \
  --external-scanner osv-scanner \
  --output security-report.md \
  --json-output security-findings.json
```

Run all supported external scanners that are installed:

```bash
dsa scan \
  --target /path/to/repo \
  --include-all-external-scanners \
  --output security-report.md \
  --json-output security-findings.json
```

For this repository's sample app:

```bash
dsa scan --target examples/insecure_service --output security-report.md
```

For the Siebel-oriented C++ and Java examples:

```bash
dsa scan --target examples/insecure_siebel_cpp --output cpp-security-report.md
dsa scan --target examples/insecure_siebel_java --output java-security-report.md
```

Verify Java REST source-to-sink traces:

```bash
dsa triage --kind java-rest --target examples/java_rest_verification --output java-rest-verification-report.md
```

Write a Java REST triage artifact for Part 2:

```bash
dsa triage \
  --kind java-rest \
  --target /path/to/java/rest/module \
  --output verification-report.md \
  --json-output verification-findings.json
```

## Deployment Validation

The validation command consumes a JSON artifact from `scan` or `triage`.

Dry-run validation plan:

```bash
dsa validate \
  --findings security-findings.json \
  --base-url https://authorized-test.example.com/siebel \
  --profile generic \
  --output validation-report.md \
  --json-output validation-report.json
```

Siebel SAM REST profile for mapped command-injection findings:

```bash
dsa validate \
  --findings verification-findings.json \
  --base-url http://HOST:PORT/bugdb \
  --profile siebel-sam-rest \
  --output sam-rest-validation-report.md
```

Execute safe validation requests only against an authorized test host:

```bash
dsa validate \
  --findings verification-findings.json \
  --base-url http://HOST:PORT/bugdb \
  --profile siebel-sam-rest \
  --execute \
  --i-understand-authorized-test \
  --allow-host HOST \
  --output sam-rest-execution-report.md
```

Execution reports include the request sent, HTTP result, manual server-side
verification step, mapped source evidence, and bug filing context. A human
reviewer must confirm server-side evidence before filing a bug as reproduced.

## Broader Sandbox Probe Validation

Use `http-probe` when the team wants to validate findings beyond built-in
profiles such as SAM REST. This profile reads a reviewed JSON probe spec that
maps findings to sandbox HTTP requests, expected indicators, and manual
verification instructions.

Template:

```bash
examples/probe_specs/http-probe-template.json
```

Dry-run:

```bash
dsa validate \
  --findings siebel-monorepo-security-findings.json \
  --base-url https://SIEBEL-SANDBOX-HOST \
  --profile http-probe \
  --probe-spec examples/probe_specs/http-probe-template.json \
  --output siebel-http-probe-plan.md
```

Execute against the DevOps-owned security sandbox:

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

Generate and execute bounded payload mutations from the reviewed probe spec:

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

Each executed case reports expected result, actual response preview, execution
note, and bug filing recommendation. The intended operating model is aggressive
coverage in a controlled sandbox, while still requiring explicit scope,
allowlisting, and human evidence review before a bug is filed.

Supported mutation locations are `query`, `json`, `header`, `body`, and `path`.
Built-in payload sets currently cover SQL input handling, XSS reflection markers,
path traversal canary checks, command-injection marker checks, and XML parser
markers. Probe specs define which endpoints and fields receive those payloads.

Current payload set names:

- `sqli-basic`
- `xss-reflection`
- `path-traversal-canary`
- `command-injection-marker`
- `xml-parser-marker`

Run tests:

```bash
python3 -m unittest discover -s tests -v
```

## Design

The agent is organized around a small pipeline:

1. Discover source files in the requested target.
2. Apply built-in defensive security heuristics.
3. Run optional tool adapters such as Semgrep when available.
4. Normalize findings into a common schema.
5. Render a Markdown report with file, line, severity, evidence, and remediation guidance.
6. Optionally emit a JSON artifact for validation planning.
7. Build a dry-run or authorized validation report from the artifact.

Future work should add:

- model-backed hypothesis generation
- C++ AST and call graph analysis with Clang tooling
- Java source-to-sink analysis
- CodeQL and SBOM adapters
- repository-specific validation profiles
- repository ownership and service metadata
- CI integration
- issue creation workflow
- sandboxed test and fuzz harnesses

## Siebel-Oriented Track

The current MVP includes first-pass C++ and Java rules for bug classes that matter in a Siebel-heavy codebase:

- unsafe C/C++ string and formatted output APIs
- C/C++ command execution
- C++ SQL string assembly
- raw C++ ownership/lifetime patterns
- Java command execution
- Java SQL string assembly
- Java native deserialization
- Java path traversal risk
- XML parser hardening gaps

## Verification Workflows

The `triage` command adds evidence-oriented analysis on top of scan findings. The first supported workflow is `java-rest`, which looks for REST-controlled Java input reaching command execution, file path construction, SQL execution, native deserialization, or XML parsing.

Trace statuses:

- `verified`: REST-controlled data reaches a sink and no basic guard evidence was found.
- `probable`: REST-controlled data reaches a sink, but guard or hardening evidence needs human review.

Example:

```bash
dsa triage --kind java-rest \
  --target /path/to/java/rest/module \
  --output verification-report.md
```

## Safety Model

This project is for defensive assessment of systems you own or are authorized to test.

The default implementation does not:

- send live validation requests
- exfiltrate secrets
- require production credentials
- modify scanned repositories

Live validation requires:

- `--execute`
- `--i-understand-authorized-test`
- at least one matching `--allow-host`

Automated validation cases are intentionally narrow and non-destructive. When a
validation result requires server-side confirmation, the report marks it as
manual verification required rather than automatically declaring success.

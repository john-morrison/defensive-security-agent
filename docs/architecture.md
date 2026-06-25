# Architecture

## Goals

Defensive Security Agent is intended to become an internal assistant for authorized code security review. It should help engineers and security reviewers find, verify, prioritize, and fix vulnerabilities in codebases they own.

## Non-Goals

- autonomous exploitation of live systems
- unmanaged production access
- unaudited credential use
- destructive validation payloads
- credential theft, data exfiltration, persistence, or lateral movement
- replacing human security review

## Components

### Orchestrator

The orchestrator owns task planning, policy checks, and report generation. It should keep an evidence log for every finding.

### Scanner

The scanner is Part 1 of the workflow. It reads a local source tree, applies
built-in and optional external checks, and emits:

- a Markdown report for human review
- a JSON artifact for downstream validation

The JSON artifact is the contract between repository assessment and deployment
validation. It includes finding IDs, file/line evidence, severity, tags,
rationale, and recommended remediation.

### Triage Verifiers

Triage verifiers add deeper evidence for specific bug classes. The initial
`java-rest` verifier identifies REST-controlled inputs that reach command
execution, file path construction, SQL execution, native deserialization, or XML
parsing sinks.

Triage also emits Markdown plus JSON so verified source-to-sink traces can feed
deployment validation.

### Validation Agent

The validation agent is Part 2 of the workflow. It consumes scan or triage JSON,
selects a validation profile, and produces a validation report.

Validation modes:

- dry-run: build human-reproducible steps only
- execute: send registered non-destructive probes to an explicitly allowlisted
  test deployment

Execution requires all of the following:

- explicit `--execute`
- explicit `--i-understand-authorized-test`
- target host present in `--allow-host`

The validation agent should not infer arbitrary exploit payloads. It should use
registered, reviewable validators that encode safe probes and clear success
criteria.

### Tool Adapters

Adapters expose bounded capabilities to the orchestrator:

- repository file discovery
- code search
- static analysis
- dependency scanning
- test execution
- fuzz harness execution
- safe deployment validation profiles
- issue tracker integration

### Validation Profiles

Validation profiles encapsulate product-specific knowledge. The first concrete
profile is `siebel-sam-rest`, which maps known SAM REST source locations to
benign command/argument-injection validation requests. The generic profile
creates manual validation plans for findings that do not yet have a registered
executor.

The `http-probe` profile broadens coverage without requiring code changes for
every new endpoint. It reads a reviewed JSON probe specification that maps
finding categories, rule IDs, tags, paths, or lines to sandbox HTTP requests,
expected indicators, manual verification instructions, and bug filing evidence.
This is the preferred path for expanding validation across EAI, Object Manager,
REST services, attachment/file handling, authorization boundaries, XML parsing,
and other deployed Siebel surfaces.

Profiles should define:

- applicable artifact types
- finding or trace matching logic
- preconditions and authorization requirements
- non-destructive request or harness steps
- manual server-side verification instructions
- cleanup instructions when applicable
- bug filing evidence requirements

### Aggressive Sandbox Mode

For a DevOps-owned security sandbox, aggressive coverage should mean:

- broad probe catalogs across known attack surfaces
- bounded automatic mutation of reviewed insertion points
- synthetic accounts, records, files, and integration payloads created for tests
- high-volume but rate-limited execution
- complete request/response/log evidence capture
- clear expected and actual result comparison
- explicit bug filing recommendation per case

It should not mean uncontrolled payload generation, destructive mutation,
credential theft, persistence, or exfiltration. Those remain out of scope for
this tool.

The `--aggressive-sandbox` flag enables bounded expansion of `http-probe` specs
using named payload sets. A probe spec still controls:

- which endpoint is tested
- which query, JSON, header, body, or path field is mutated
- which payload set is allowed for that field
- how many mutations may be generated
- which expected indicators and server-side evidence decide bug filing

### Model Layer

The model layer should be introduced behind a narrow interface:

- summarize attack surface
- infer likely trust boundaries
- propose vulnerability hypotheses
- rank findings
- draft fixes

The model should not directly access credentials, production networks, or arbitrary command execution.

### Evidence Store

Each finding should retain:

- file and line
- rule or hypothesis source
- code evidence
- verification steps
- affected component
- recommended fix
- residual uncertainty

## Initial Workflow

```text
target repo
  -> file discovery
  -> builtin rules
  -> optional scanners
  -> normalized findings
  -> Markdown report
  -> JSON artifact
```

## Validation Workflow

```text
scan/triage JSON artifact
  -> validation profile selection
  -> dry-run validation cases
  -> optional authorized execution
  -> Markdown/JSON validation report
  -> human-reviewed bug filing
```

## Future Workflow

```text
target repo
  -> attack-surface map
  -> model hypotheses
  -> static and dynamic verification
  -> ranked findings
  -> human-approved fix PR
```

## Validation Result Semantics

The validation report should distinguish:

- `planned`: dry-run steps were generated, no live request sent
- `manual-verification-required`: a safe request was sent, but server-side
  evidence must be confirmed by a human
- `network-error`: the request was not delivered
- `blocked`: no approved automated executor exists for the finding

The tool should not mark a finding as successfully exploited unless the relevant
validator has objective, authorized evidence for that conclusion.

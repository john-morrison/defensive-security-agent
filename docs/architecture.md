# Architecture

## Goals

Defensive Security Agent is intended to become an internal assistant for authorized code security review. It should help engineers and security reviewers find, verify, prioritize, and fix vulnerabilities in codebases they own.

## Non-Goals

- autonomous exploitation of live systems
- unmanaged production access
- unaudited credential use
- replacing human security review

## Components

### Orchestrator

The orchestrator owns task planning, policy checks, and report generation. It should keep an evidence log for every finding.

### Tool Adapters

Adapters expose bounded capabilities to the orchestrator:

- repository file discovery
- code search
- static analysis
- dependency scanning
- test execution
- fuzz harness execution
- issue tracker integration

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
target repo -> file discovery -> builtin rules -> optional scanners -> normalized findings -> report
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


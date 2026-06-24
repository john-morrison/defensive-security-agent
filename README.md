# Defensive Security Agent

A defensive code-security agent scaffold for internal repositories.

The first version is intentionally conservative:

- reads local source trees only
- runs heuristic risk checks
- optionally runs external scanners when present
- writes evidence-backed Markdown reports
- avoids autonomous exploitation or production access

## Quick Start

Install the local CLI in editable mode:

```bash
python3 -m pip install -e .
```

```bash
dsa scan --target /path/to/repo --output security-report.md
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

Future work should add:

- model-backed hypothesis generation
- C++ AST and call graph analysis with Clang tooling
- Java source-to-sink analysis
- CodeQL and SBOM adapters
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

## Safety Model

This project is for defensive assessment of systems you own or are authorized to test.

The default implementation does not:

- attack live services
- exploit vulnerabilities
- exfiltrate secrets
- require production credentials
- modify scanned repositories

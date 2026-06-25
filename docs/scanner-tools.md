# External Scanner Prerequisites And Usage

Defensive Security Agent works without external tools because it has built-in
rules. For stronger coverage, install one or more free/open-source scanners and
ask `dsa scan` to run them.

You do not need to install every tool on this page. Start with the recommended
set, then add more as needed.

## Required Base Prerequisites

Install Python 3.10 or newer.

Check:

```bash
python3 --version
```

Install this project in editable mode:

```bash
cd /Users/johnm/codex_general/my_projects/defensive-security-agent
python3 -m pip install -e .
```

Check the CLI:

```bash
dsa --help
```

If `dsa` is not on your path, use:

```bash
PYTHONPATH=src python3 -m dsa --help
```

## Recommended Starter Tool Set

For most users, start with:

- `semgrep` for general source-code SAST
- `gitleaks` or `detect-secrets` for secrets
- `osv-scanner` or `grype` for dependency vulnerabilities
- `bandit` if the repo contains Python
- `checkov` if the repo contains infrastructure-as-code

For Siebel-heavy Java/C++ repositories, the built-in DSA rules and Semgrep are
the first useful baseline. Dependency and secret scanners are still valuable
because monorepos often contain scripts, tooling, test apps, package manifests,
and configuration files.

## Supported External Scanners

| Scanner | Purpose | DSA name |
| --- | --- | --- |
| Semgrep | General source-code SAST | `semgrep` |
| Bandit | Python security checks | `bandit` |
| pip-audit | Python dependency vulnerabilities | `pip-audit` |
| npm audit | JavaScript dependency vulnerabilities | `npm-audit` |
| Gitleaks | Secret scanning | `gitleaks` |
| detect-secrets | Secret scanning | `detect-secrets` |
| Checkov | Infrastructure-as-code scanning | `checkov` |
| OSV-Scanner | Dependency vulnerability scanning | `osv-scanner` |
| Grype | Dependency/container vulnerability scanning | `grype` |
| Gosec | Go security checks | `gosec` |

## Installation Examples

These are common install methods. Your machine or corporate environment may
prefer different package managers.

### Python-Based Tools

```bash
python3 -m pip install semgrep bandit pip-audit detect-secrets checkov
```

Verify:

```bash
semgrep --version
bandit --version
pip-audit --version
detect-secrets --version
checkov --version
```

### macOS Homebrew Tools

```bash
brew install gitleaks osv-scanner grype gosec
```

Verify:

```bash
gitleaks version
osv-scanner --version
grype version
gosec --version
```

### npm audit

`npm audit` is part of npm. Install Node.js/npm if needed:

```bash
node --version
npm --version
```

If those commands are missing, install Node.js using your approved package
manager.

## How To Run One External Scanner

Example with Semgrep:

```bash
dsa scan \
  --target /Users/johnm/codex_general/my_projects/siebel-monorepo \
  --external-scanner semgrep \
  --output siebel-semgrep-report.md \
  --json-output siebel-semgrep-findings.json
```

Example with Gitleaks:

```bash
dsa scan \
  --target /Users/johnm/codex_general/my_projects/siebel-monorepo \
  --external-scanner gitleaks \
  --output siebel-gitleaks-report.md \
  --json-output siebel-gitleaks-findings.json
```

## How To Run Multiple External Scanners

Repeat `--external-scanner`:

```bash
dsa scan \
  --target /Users/johnm/codex_general/my_projects/siebel-monorepo \
  --external-scanner semgrep \
  --external-scanner gitleaks \
  --external-scanner osv-scanner \
  --output siebel-combined-report.md \
  --json-output siebel-combined-findings.json
```

DSA will:

1. run built-in rules
2. run each requested external scanner if installed
3. normalize results into one report
4. include missing-tool or scanner warnings under Tool Notes

## How To Run All Supported External Scanners

Use this when you want maximum installed-tool coverage:

```bash
dsa scan \
  --target /Users/johnm/codex_general/my_projects/siebel-monorepo \
  --include-all-external-scanners \
  --output siebel-all-tools-report.md \
  --json-output siebel-all-tools-findings.json
```

If a tool is not installed, DSA records a note and continues. It does not fail
the entire scan because one optional scanner is missing.

## Backward-Compatible Semgrep Shortcut

This still works:

```bash
dsa scan \
  --target /Users/johnm/codex_general/my_projects/siebel-monorepo \
  --include-semgrep \
  --output siebel-security-report.md \
  --json-output siebel-security-findings.json
```

It is equivalent to:

```bash
dsa scan \
  --target /Users/johnm/codex_general/my_projects/siebel-monorepo \
  --external-scanner semgrep \
  --output siebel-security-report.md \
  --json-output siebel-security-findings.json
```

## Tool-Specific Notes

### Semgrep

Best for general source-code security patterns across many languages.

Run:

```bash
dsa scan --target /path/to/repo --external-scanner semgrep --output report.md
```

### Bandit

Best for Python code.

Run:

```bash
dsa scan --target /path/to/repo --external-scanner bandit --output report.md
```

### pip-audit

Best for Python dependency vulnerabilities.

Run:

```bash
dsa scan --target /path/to/repo --external-scanner pip-audit --output report.md
```

### npm audit

Best for JavaScript/TypeScript projects with `package.json` and lock files.

Run:

```bash
dsa scan --target /path/to/repo --external-scanner npm-audit --output report.md
```

### Gitleaks

Best for finding committed secrets.

Run:

```bash
dsa scan --target /path/to/repo --external-scanner gitleaks --output report.md
```

### detect-secrets

Best for secret scanning with a Python-based toolchain.

Run:

```bash
dsa scan --target /path/to/repo --external-scanner detect-secrets --output report.md
```

### Checkov

Best for infrastructure-as-code such as Terraform, Kubernetes manifests, Docker,
and cloud configuration.

Run:

```bash
dsa scan --target /path/to/repo --external-scanner checkov --output report.md
```

### OSV-Scanner

Best for dependency vulnerability scanning using OSV data.

Run:

```bash
dsa scan --target /path/to/repo --external-scanner osv-scanner --output report.md
```

### Grype

Best for dependency and container vulnerability scanning.

Run:

```bash
dsa scan --target /path/to/repo --external-scanner grype --output report.md
```

### Gosec

Best for Go source code.

Run:

```bash
dsa scan --target /path/to/go/module --external-scanner gosec --output report.md
```

## Recommended Full Scan For The Siebel Monorepo

Start with:

```bash
dsa scan \
  --target /Users/johnm/codex_general/my_projects/siebel-monorepo \
  --external-scanner semgrep \
  --external-scanner gitleaks \
  --external-scanner osv-scanner \
  --output siebel-security-report.md \
  --json-output siebel-security-findings.json
```

Then add more scanners depending on what exists in the repo:

```bash
dsa scan \
  --target /Users/johnm/codex_general/my_projects/siebel-monorepo \
  --external-scanner semgrep \
  --external-scanner gitleaks \
  --external-scanner osv-scanner \
  --external-scanner grype \
  --external-scanner checkov \
  --external-scanner bandit \
  --external-scanner npm-audit \
  --output siebel-security-expanded-report.md \
  --json-output siebel-security-expanded-findings.json
```

## What Happens If A Tool Is Missing

The scan still runs. The report includes a Tool Notes section like:

```text
gitleaks was requested but `gitleaks` was not found.
```

Install the missing tool and rerun the scan if you need that coverage.

## Next Step After Scanning

Use the JSON artifact with validation:

```bash
dsa validate \
  --findings siebel-security-findings.json \
  --base-url https://SIEBEL-SANDBOX-HOST \
  --profile generic \
  --output siebel-validation-plan.md
```

Or use `http-probe` with a reviewed probe spec:

```bash
dsa validate \
  --findings siebel-security-findings.json \
  --base-url https://SIEBEL-SANDBOX-HOST \
  --profile http-probe \
  --probe-spec examples/probe_specs/http-probe-template.json \
  --output siebel-http-probe-plan.md
```

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern

from .findings import Severity


@dataclass(frozen=True)
class RegexRule:
    rule_id: str
    title: str
    severity: Severity
    pattern: Pattern[str]
    rationale: str
    recommendation: str
    tags: tuple[str, ...]


BUILTIN_RULES: tuple[RegexRule, ...] = (
    RegexRule(
        rule_id="dsa.sql.string-interpolation",
        title="Possible SQL query construction from string interpolation",
        severity="high",
        pattern=re.compile(
            r"(?i)(execute|query|raw)\s*\([^)]*(f[\"']|%|\+|\.format\()"
        ),
        rationale=(
            "Dynamic SQL construction can allow injection when user-controlled "
            "values reach the query string."
        ),
        recommendation=(
            "Use parameterized queries or a query builder that keeps SQL text "
            "separate from values."
        ),
        tags=("injection", "database"),
    ),
    RegexRule(
        rule_id="dsa.shell.shell-true",
        title="Shell command execution with shell=True",
        severity="high",
        pattern=re.compile(r"subprocess\.(run|Popen|call|check_call|check_output)\([^)]*shell\s*=\s*True"),
        rationale=(
            "shell=True expands metacharacters and can turn tainted input into "
            "command injection."
        ),
        recommendation=(
            "Pass an argument list with shell=False and validate any user-controlled "
            "arguments."
        ),
        tags=("command-injection", "process"),
    ),
    RegexRule(
        rule_id="dsa.crypto.md5-sha1",
        title="Weak hash primitive",
        severity="medium",
        pattern=re.compile(r"(?i)\b(md5|sha1)\s*\("),
        rationale="MD5 and SHA-1 are not appropriate for security-sensitive hashing.",
        recommendation=(
            "Use SHA-256 or stronger for non-password integrity checks. Use a "
            "password hashing function such as Argon2id, bcrypt, or scrypt for passwords."
        ),
        tags=("crypto",),
    ),
    RegexRule(
        rule_id="dsa.secrets.inline-secret",
        title="Possible hard-coded secret",
        severity="high",
        pattern=re.compile(
            r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*[\"'][^\"']{12,}[\"']"
        ),
        rationale="Hard-coded credentials can leak through source control and logs.",
        recommendation=(
            "Move secrets to an approved secret manager and rotate any exposed value."
        ),
        tags=("secret",),
    ),
    RegexRule(
        rule_id="dsa.web.debug-mode",
        title="Debug mode may be enabled",
        severity="medium",
        pattern=re.compile(r"(?i)\bdebug\s*=\s*true\b"),
        rationale="Debug mode can expose stack traces, environment details, or unsafe tools.",
        recommendation="Disable debug mode outside local development.",
        tags=("configuration", "web"),
    ),
    RegexRule(
        rule_id="dsa.deserialization.pickle",
        title="Unsafe Python deserialization primitive",
        severity="high",
        pattern=re.compile(r"\bpickle\.loads?\s*\("),
        rationale="Pickle can execute code during deserialization of untrusted data.",
        recommendation=(
            "Use a safe data format such as JSON for untrusted input. If pickle is "
            "required, restrict it to trusted, authenticated data."
        ),
        tags=("deserialization", "python"),
    ),
)


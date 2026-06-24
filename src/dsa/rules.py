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
    extensions: tuple[str, ...] = ()


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
        extensions=(".py", ".js", ".jsx", ".ts", ".tsx"),
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
        extensions=(".py",),
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
        extensions=(".py",),
    ),
    RegexRule(
        rule_id="dsa.cpp.unsafe-string-copy",
        title="Unsafe C/C++ string copy function",
        severity="high",
        pattern=re.compile(r"\b(strcpy|strcat|wcscpy|wcscat)\s*\("),
        rationale=(
            "Unbounded string copy and concatenation functions are common sources "
            "of buffer overflows in C and C++ code."
        ),
        recommendation=(
            "Use bounded APIs or project-approved safe string abstractions, and "
            "validate destination buffer sizes."
        ),
        tags=("cpp", "memory-safety", "buffer-overflow"),
        extensions=(".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"),
    ),
    RegexRule(
        rule_id="dsa.cpp.unsafe-format",
        title="Unsafe C/C++ formatted output function",
        severity="high",
        pattern=re.compile(r"\b(sprintf|vsprintf|swprintf|vswprintf)\s*\("),
        rationale=(
            "Unbounded formatted output can overflow destination buffers or create "
            "format string risks when format values are not trusted."
        ),
        recommendation=(
            "Use bounded formatting with explicit buffer sizes and keep format "
            "strings constant."
        ),
        tags=("cpp", "memory-safety", "format-string"),
        extensions=(".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"),
    ),
    RegexRule(
        rule_id="dsa.cpp.raw-command-exec",
        title="C/C++ command execution primitive",
        severity="high",
        pattern=re.compile(r"\b(system|popen|execl|execlp|execle|execv|execvp|execvpe)\s*\("),
        rationale=(
            "Command execution primitives can become command injection when any "
            "argument is influenced by external input."
        ),
        recommendation=(
            "Avoid shell invocation. Use a fixed executable with validated arguments "
            "and a project-approved process wrapper."
        ),
        tags=("cpp", "command-injection", "process"),
        extensions=(".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"),
    ),
    RegexRule(
        rule_id="dsa.cpp.sql-concat",
        title="Possible C++ SQL string construction",
        severity="high",
        pattern=re.compile(
            r'(?i)(select|insert|update|delete)\b[^;\n]*(\+|append\s*\(|<<|strcat\s*\()'
        ),
        rationale=(
            "SQL assembled through string concatenation can permit injection and "
            "can bypass approved data-access patterns."
        ),
        recommendation=(
            "Use bind variables, parameterized query APIs, or the approved Siebel "
            "data-access abstraction."
        ),
        tags=("cpp", "injection", "database", "siebel"),
        extensions=(".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"),
    ),
    RegexRule(
        rule_id="dsa.cpp.raw-new-delete",
        title="Raw C++ memory management",
        severity="medium",
        pattern=re.compile(r"\b(new\s+[\w:]+|delete\s+[\w*\[\]])"),
        rationale=(
            "Raw allocation and deletion increase the risk of leaks, double frees, "
            "use-after-free defects, and exception-unsafe cleanup."
        ),
        recommendation=(
            "Prefer RAII ownership types such as std::unique_ptr, std::shared_ptr, "
            "standard containers, or project-approved lifetime wrappers."
        ),
        tags=("cpp", "memory-safety", "lifetime"),
        extensions=(".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"),
    ),
    RegexRule(
        rule_id="dsa.cpp.xml-external-entity-risk",
        title="C++ XML parser external entity risk",
        severity="medium",
        pattern=re.compile(r"\b(load_file|LoadFile|ParseFile|parseFile|setValidationScheme)\s*\("),
        rationale=(
            "XML file parsing and validation features can expose XXE, SSRF, or local "
            "file disclosure when external entities and network access are enabled."
        ),
        recommendation=(
            "Disable external entity resolution and network fetches for untrusted XML. "
            "Use hardened parser configuration by default."
        ),
        tags=("cpp", "xml", "xxe"),
        extensions=(".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"),
    ),
    RegexRule(
        rule_id="dsa.java.runtime-exec",
        title="Java command execution primitive",
        severity="high",
        pattern=re.compile(r"\b(Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\("),
        rationale=(
            "Java process execution can become command injection when command or "
            "argument values are influenced by external input."
        ),
        recommendation=(
            "Avoid command execution on request-controlled data. Use fixed commands, "
            "argument allowlists, and safer internal APIs where possible."
        ),
        tags=("java", "command-injection", "process"),
        extensions=(".java",),
    ),
    RegexRule(
        rule_id="dsa.java.sql-concat",
        title="Possible Java SQL string construction",
        severity="high",
        pattern=re.compile(
            r'(?i)(executeQuery|executeUpdate|prepareStatement|createStatement)\s*\([^;\n]*(\+|String\.format)'
        ),
        rationale=(
            "SQL assembled from strings can permit injection when values are derived "
            "from requests, integration payloads, or workflow inputs."
        ),
        recommendation=(
            "Use PreparedStatement with bind variables and avoid concatenating SQL "
            "fragments with untrusted values."
        ),
        tags=("java", "injection", "database"),
        extensions=(".java",),
    ),
    RegexRule(
        rule_id="dsa.java.unsafe-deserialization",
        title="Java native deserialization",
        severity="high",
        pattern=re.compile(r"\bnew\s+ObjectInputStream\s*\("),
        rationale=(
            "Java native deserialization can execute gadget chains when reading "
            "untrusted data."
        ),
        recommendation=(
            "Avoid native Java deserialization for untrusted input. Use a safe data "
            "format and enforce allowlists when legacy deserialization is unavoidable."
        ),
        tags=("java", "deserialization"),
        extensions=(".java",),
    ),
    RegexRule(
        rule_id="dsa.java.path-traversal-risk",
        title="Java file path built from variable input",
        severity="medium",
        pattern=re.compile(r"\bnew\s+File\s*\([^;\n]*(\+|request|getParameter|getHeader)"),
        rationale=(
            "File paths built from external input can allow path traversal or access "
            "outside the intended directory."
        ),
        recommendation=(
            "Normalize the path, reject traversal sequences, and verify the resolved "
            "path remains under an approved base directory."
        ),
        tags=("java", "path-traversal", "filesystem"),
        extensions=(".java",),
    ),
    RegexRule(
        rule_id="dsa.java.weak-xml-parser",
        title="Java XML parser created without visible hardening",
        severity="medium",
        pattern=re.compile(r"\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\("),
        rationale=(
            "Default XML parser settings may allow external entities or network "
            "fetches unless hardened features are explicitly disabled."
        ),
        recommendation=(
            "Disable DOCTYPE declarations, external entities, and external DTD/schema "
            "loading before parsing untrusted XML."
        ),
        tags=("java", "xml", "xxe"),
        extensions=(".java",),
    ),
)

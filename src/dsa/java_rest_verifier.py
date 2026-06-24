from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


JAVA_EXTENSIONS = {".java"}

REST_ANNOTATIONS = (
    "@RequestMapping",
    "@GetMapping",
    "@PostMapping",
    "@PutMapping",
    "@DeleteMapping",
    "@PatchMapping",
    "@Path",
)

SOURCE_ANNOTATIONS = (
    "@PathVariable",
    "@RequestParam",
    "@RequestBody",
    "@RequestHeader",
    "@CookieValue",
)

GUARD_PATTERNS = (
    "matches(",
    "Pattern.matches",
    ".matcher(",
    "isValid(",
    "validate(",
    "Validator",
    "allowlist",
    "whitelist",
    "canonical",
    "normalize",
    "getCanonicalPath",
    "toRealPath",
)


@dataclass(frozen=True)
class VerificationTrace:
    status: str
    bug_class: str
    path: Path
    method_name: str
    method_line: int
    source_line: int
    source_evidence: str
    sink_line: int
    sink_evidence: str
    tainted_symbols: tuple[str, ...]
    guard_evidence: tuple[str, ...] = field(default_factory=tuple)
    rationale: str = ""
    recommendation: str = ""


@dataclass(frozen=True)
class VerificationResult:
    target: Path
    scanned_files: int
    traces: tuple[VerificationTrace, ...]
    notes: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class JavaMethod:
    name: str
    path: Path
    start_line: int
    end_line: int
    annotations: tuple[str, ...]
    signature: str
    lines: tuple[tuple[int, str], ...]


@dataclass
class TaintInfo:
    source_line: int
    source_evidence: str


def verify_java_rest_target(target: Path, max_file_kb: int = 512) -> VerificationResult:
    if not target.exists():
        raise FileNotFoundError(f"target does not exist: {target}")

    files = _iter_java_files(target, max_file_kb=max_file_kb)
    traces: list[VerificationTrace] = []
    notes: list[str] = []

    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            notes.append(f"Could not read {path}: {exc}")
            continue
        for method in _extract_java_methods(path, text):
            if _is_rest_method(method):
                traces.extend(_verify_method(method))

    traces.sort(key=lambda trace: (str(trace.path), trace.sink_line, trace.bug_class))
    return VerificationResult(
        target=target,
        scanned_files=len(files),
        traces=tuple(traces),
        notes=tuple(notes),
    )


def _iter_java_files(target: Path, max_file_kb: int) -> list[Path]:
    if target.is_file():
        return [target] if _is_java_file(target, max_file_kb) else []
    return [
        path
        for path in target.rglob("*.java")
        if ".git" not in path.parts and _is_java_file(path, max_file_kb)
    ]


def _is_java_file(path: Path, max_file_kb: int) -> bool:
    try:
        return path.suffix in JAVA_EXTENSIONS and path.stat().st_size <= max_file_kb * 1024
    except OSError:
        return False


def _extract_java_methods(path: Path, text: str) -> list[JavaMethod]:
    numbered = list(enumerate(text.splitlines(), start=1))
    methods: list[JavaMethod] = []
    annotations: list[str] = []
    index = 0

    while index < len(numbered):
        line_number, line = numbered[index]
        stripped = line.strip()
        if stripped.startswith("@"):
            annotations.append(stripped)
            index += 1
            continue

        if _looks_like_method_start(stripped):
            signature_lines = [stripped]
            signature_start = line_number
            while "{" not in signature_lines[-1] and index + 1 < len(numbered):
                index += 1
                signature_lines.append(numbered[index][1].strip())

            signature = " ".join(signature_lines)
            name = _method_name(signature)
            body_lines: list[tuple[int, str]] = []
            brace_depth = 0
            started = False
            while index < len(numbered):
                current_number, current_line = numbered[index]
                body_lines.append((current_number, current_line))
                code = _strip_line_comment(current_line)
                brace_depth += code.count("{")
                if "{" in code:
                    started = True
                brace_depth -= code.count("}")
                if started and brace_depth <= 0:
                    break
                index += 1

            methods.append(
                JavaMethod(
                    name=name,
                    path=path,
                    start_line=signature_start,
                    end_line=body_lines[-1][0] if body_lines else signature_start,
                    annotations=tuple(annotations),
                    signature=signature,
                    lines=tuple(body_lines),
                )
            )
            annotations = []
            index += 1
            continue

        if stripped and not stripped.startswith("@"):
            annotations = []
        index += 1

    return methods


def _looks_like_method_start(stripped: str) -> bool:
    if "(" not in stripped or stripped.startswith(("if ", "for ", "while ", "switch ", "catch ")):
        return False
    if stripped.endswith(";"):
        return False
    return bool(
        re.search(
            r"\b(public|private|protected)\b\s+(static\s+)?[\w<>\[\], ?]+\s+\w+\s*\(",
            stripped,
        )
    )


def _method_name(signature: str) -> str:
    match = re.search(
        r"\b(?:public|private|protected)\b\s+(?:static\s+)?[\w<>\[\], ?]+\s+(\w+)\s*\(",
        signature,
    )
    return match.group(1) if match else "unknown"


def _is_rest_method(method: JavaMethod) -> bool:
    joined = "\n".join(method.annotations) + "\n" + method.signature
    if any(annotation in joined for annotation in REST_ANNOTATIONS):
        return True
    return any(annotation in joined for annotation in SOURCE_ANNOTATIONS)


def _verify_method(method: JavaMethod) -> list[VerificationTrace]:
    tainted: dict[str, TaintInfo] = _initial_taint(method)
    traces: list[VerificationTrace] = []
    statements = _statements(method.lines)

    for start_line, statement in statements:
        stripped = " ".join(statement.strip().split())
        if not stripped:
            continue

        if _is_command_sink(stripped):
            trace = _trace_if_tainted(
                method,
                tainted,
                start_line,
                stripped,
                "command-injection",
                "REST-controlled data reaches a process execution sink.",
                "Use fixed commands and argument arrays. Reject or allowlist request-controlled values before process execution.",
            )
            if trace:
                traces.append(trace)

        if _is_file_sink(stripped):
            trace = _trace_if_tainted(
                method,
                tainted,
                start_line,
                stripped,
                "path-traversal",
                "REST-controlled data reaches filesystem path construction.",
                "Resolve paths against an approved base directory and verify the canonical path remains inside it.",
            )
            if trace:
                traces.append(trace)

        if _is_sql_sink(stripped):
            trace = _trace_if_tainted(
                method,
                tainted,
                start_line,
                stripped,
                "sql-injection",
                "REST-controlled data reaches SQL execution or statement construction.",
                "Use PreparedStatement bind variables or approved data-access APIs without concatenating request-controlled values.",
            )
            if trace:
                traces.append(trace)

        if _is_deserialization_sink(stripped):
            trace = _trace_if_tainted(
                method,
                tainted,
                start_line,
                stripped,
                "unsafe-deserialization",
                "REST-controlled data reaches Java native deserialization.",
                "Avoid ObjectInputStream on request data. Use safe formats and allowlists for legacy deserialization.",
            )
            if trace:
                traces.append(trace)

        _propagate_taint(stripped, start_line, tainted)

    traces.extend(_xml_parser_traces(method))
    return traces


def _initial_taint(method: JavaMethod) -> dict[str, TaintInfo]:
    tainted: dict[str, TaintInfo] = {}
    signature = method.signature
    params = _parameter_fragments(signature)
    for fragment in params:
        if any(annotation in fragment for annotation in SOURCE_ANNOTATIONS):
            name = _last_identifier(fragment)
            if name:
                tainted[name] = TaintInfo(method.start_line, fragment.strip())
        elif "HttpServletRequest" in fragment or "ServletRequest" in fragment:
            name = _last_identifier(fragment)
            if name:
                tainted[name] = TaintInfo(method.start_line, fragment.strip())
    return tainted


def _parameter_fragments(signature: str) -> list[str]:
    match = re.search(r"\((.*)\)", signature)
    if not match:
        return []
    params = []
    current: list[str] = []
    depth = 0
    for char in match.group(1):
        if char in "(<":
            depth += 1
        elif char in ")>" and depth > 0:
            depth -= 1
        if char == "," and depth == 0:
            params.append("".join(current))
            current = []
        else:
            current.append(char)
    if current:
        params.append("".join(current))
    return params


def _last_identifier(fragment: str) -> str | None:
    identifiers = re.findall(r"\b[A-Za-z_]\w*\b", fragment)
    if not identifiers:
        return None
    return identifiers[-1]


def _statements(lines: tuple[tuple[int, str], ...]) -> list[tuple[int, str]]:
    statements: list[tuple[int, str]] = []
    current: list[str] = []
    start_line = 0
    for line_number, line in lines:
        stripped = _strip_line_comment(line).strip()
        if not stripped:
            continue
        if not current:
            start_line = line_number
        current.append(stripped)
        if ";" in stripped or stripped.endswith("{") or stripped.endswith("}"):
            statements.append((start_line, " ".join(current)))
            current = []
    if current:
        statements.append((start_line, " ".join(current)))
    return statements


def _strip_line_comment(line: str) -> str:
    return re.split(r"(?<!:)//", line, maxsplit=1)[0]


def _propagate_taint(statement: str, line: int, tainted: dict[str, TaintInfo]) -> None:
    request_source = re.search(r"\b(\w+)\.get(Parameter|Header|Cookies?)\s*\(", statement)
    if request_source:
        assigned = _assigned_variable(statement)
        if assigned:
            tainted[assigned] = TaintInfo(line, statement[:240])

    assigned = _assigned_variable(statement)
    if assigned and _contains_tainted_symbol(statement, tainted):
        source = _first_taint(statement, tainted)
        if source:
            tainted[assigned] = source


def _assigned_variable(statement: str) -> str | None:
    match = re.search(r"(?:^|[;{]\s*)(?:[\w<>\[\], ?]+\s+)?([A-Za-z_]\w*)\s*=", statement)
    if match:
        return match.group(1)
    return None


def _contains_tainted_symbol(statement: str, tainted: dict[str, TaintInfo]) -> bool:
    if re.search(r"\.get(Parameter|Header|Cookies?)\s*\(", statement):
        return True
    return any(re.search(rf"\b{re.escape(symbol)}\b", statement) for symbol in tainted)


def _first_taint(statement: str, tainted: dict[str, TaintInfo]) -> TaintInfo | None:
    for symbol, info in tainted.items():
        if re.search(rf"\b{re.escape(symbol)}\b", statement):
            return info
    return None


def _tainted_symbols_in(statement: str, tainted: dict[str, TaintInfo]) -> tuple[str, ...]:
    return tuple(
        symbol
        for symbol in sorted(tainted)
        if re.search(rf"\b{re.escape(symbol)}\b", statement)
    )


def _is_command_sink(statement: str) -> bool:
    return "Runtime.getRuntime().exec" in statement or "new ProcessBuilder" in statement


def _is_file_sink(statement: str) -> bool:
    return bool(re.search(r"\bnew\s+File\s*\(", statement))


def _is_sql_sink(statement: str) -> bool:
    return bool(
        re.search(
            r"\b(executeQuery|executeUpdate|execute|prepareStatement|createStatement)\s*\(",
            statement,
        )
    )


def _is_deserialization_sink(statement: str) -> bool:
    return "new ObjectInputStream" in statement


def _trace_if_tainted(
    method: JavaMethod,
    tainted: dict[str, TaintInfo],
    sink_line: int,
    sink_statement: str,
    bug_class: str,
    rationale: str,
    recommendation: str,
) -> VerificationTrace | None:
    if not _contains_tainted_symbol(sink_statement, tainted):
        return None

    source = _first_taint(sink_statement, tainted)
    if source is None:
        source = TaintInfo(sink_line, "request-derived expression")

    guards = _guard_evidence(method)
    status = "probable" if guards else "verified"
    tainted_symbols = _tainted_symbols_in(sink_statement, tainted)
    return VerificationTrace(
        status=status,
        bug_class=bug_class,
        path=method.path,
        method_name=method.name,
        method_line=method.start_line,
        source_line=source.source_line,
        source_evidence=source.source_evidence,
        sink_line=sink_line,
        sink_evidence=sink_statement[:240],
        tainted_symbols=tainted_symbols,
        guard_evidence=guards,
        rationale=rationale,
        recommendation=recommendation,
    )


def _guard_evidence(method: JavaMethod) -> tuple[str, ...]:
    evidence: list[str] = []
    for _, line in method.lines:
        stripped = line.strip()
        if any(pattern in stripped for pattern in GUARD_PATTERNS):
            evidence.append(stripped[:200])
        if len(evidence) >= 5:
            break
    return tuple(evidence)


def _xml_parser_traces(method: JavaMethod) -> list[VerificationTrace]:
    traces: list[VerificationTrace] = []
    factory_vars: dict[str, int] = {}
    hardened_vars: set[str] = set()
    tainted = _initial_taint(method)

    for start_line, statement in _statements(method.lines):
        stripped = " ".join(statement.strip().split())
        _propagate_taint(stripped, start_line, tainted)
        factory_match = re.search(
            r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\s+(\w+)\s*=\s*(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(",
            stripped,
        )
        if factory_match:
            factory_vars[factory_match.group(1)] = start_line
            continue

        for var in tuple(factory_vars):
            if var in stripped and (
                "setFeature" in stripped
                or "setProperty" in stripped
                or "setExpandEntityReferences(false)" in stripped
                or "SUPPORT_DTD" in stripped
                or "ACCESS_EXTERNAL" in stripped
            ):
                hardened_vars.add(var)

            if var in stripped and ".parse(" in stripped and _contains_tainted_symbol(stripped, tainted):
                source = _first_taint(stripped, tainted) or TaintInfo(start_line, "request-derived XML input")
                status = "probable" if var in hardened_vars else "verified"
                guard_evidence = _xml_guard_evidence(method, var)
                traces.append(
                    VerificationTrace(
                        status=status,
                        bug_class="xxe",
                        path=method.path,
                        method_name=method.name,
                        method_line=method.start_line,
                        source_line=source.source_line,
                        source_evidence=source.source_evidence,
                        sink_line=start_line,
                        sink_evidence=stripped[:240],
                        tainted_symbols=_tainted_symbols_in(stripped, tainted),
                        guard_evidence=guard_evidence,
                        rationale="REST-controlled XML is parsed by a Java XML parser.",
                        recommendation="Disable DOCTYPE, external entities, external DTD/schema loading, and external protocols before parsing request-controlled XML.",
                    )
                )
    return traces


def _xml_guard_evidence(method: JavaMethod, var: str) -> tuple[str, ...]:
    evidence: list[str] = []
    for _, line in method.lines:
        stripped = line.strip()
        if var in stripped and (
            "setFeature" in stripped
            or "setProperty" in stripped
            or "setExpandEntityReferences" in stripped
        ):
            evidence.append(stripped[:200])
    return tuple(evidence[:5])

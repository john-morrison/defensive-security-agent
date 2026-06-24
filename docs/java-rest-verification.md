# Java REST Verification

The Java REST verifier is the first step from pattern findings to verified vulnerabilities.

It identifies method-local source-to-sink traces:

- sources: `@PathVariable`, `@RequestParam`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, and servlet request parameters
- sinks: `Runtime.getRuntime().exec`, `ProcessBuilder`, `new File`, SQL execution APIs, `ObjectInputStream`, and Java XML parser usage
- guards: allowlist-style checks, regex checks, canonicalization, normalization, XML parser hardening calls

## Statuses

- `verified`: request-controlled data reaches a dangerous sink and the verifier did not find basic guard evidence.
- `probable`: request-controlled data reaches a dangerous sink, but guard evidence exists and needs human review.

The verifier is intentionally conservative about the word "verified": it verifies a same-method data path from a REST input to a sink. It does not yet prove exploitability against a running service, authorization reachability, or deployment exposure.

## Current Limits

- method-local propagation only
- regex-based parsing rather than Java AST parsing
- basic guard recognition only
- no interprocedural call graph
- no framework route inventory

## Next Increments

- add JavaParser or Spoon-backed AST parsing
- follow values through helper methods
- identify authentication and authorization annotations
- classify routes by exposure
- generate reproduction notes or tests for each verified command/file/SQL trace


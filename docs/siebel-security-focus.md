# Siebel Security Focus

The first Siebel-oriented analyzer track prioritizes C++ and Java issues that generic scanners often report too late or without enough product context.

## Initial Bug Classes

- unsafe C/C++ string and buffer handling
- C/C++ command execution
- C++ SQL string assembly
- raw C++ ownership and lifetime hazards
- Java command execution
- Java SQL string assembly
- Java native deserialization
- Java file path construction from variable input
- XML parser hardening gaps

## Product-Specific Direction

Future Siebel-specific rules should encode project knowledge, including:

- approved data-access APIs
- approved string and buffer wrappers
- visibility and access-control invariants
- safe attachment and file handling patterns
- safe EAI and integration payload parsing
- unsafe legacy helpers that require human review
- code paths reachable from Object Manager, EAI, workflow, and external adapters

## Next Analyzer Increment

The current scanner is line-oriented. The next increment should add parser-backed context so it can detect multi-line calls, source-to-sink flows, function wrappers, and project-specific safe abstractions with fewer false positives.

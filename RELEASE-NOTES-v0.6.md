# JEP v0.6 Draft Set — Engineering-Complete Seed Pass

This package continues the v0.6 draft set and adds engineering artifacts inside the same version.

## Included drafts

- `draft-wang-jep-judgment-event-protocol-06.md`
- `draft-wang-jep-profiles-00.md`
- `draft-wang-jep-conformance-00.md`

## Existing v0.6 seed contents

- Cross-document references between Core, Profiles, and Conformance.
- Signed Ed25519/JWS/JCS baseline vectors.
- Canonical unsigned payload and event-hash fixtures.
- JSON Schemas for events, references, extensions, profiles, signatures, and validation results.
- Python, TypeScript, and Go validator seeds.
- Invalid vectors, profile examples, implementation guides, and IETF-style rendered sources.

## 0.6.1 implementation-alignment pass

This pass changes executable artifacts and conformance evidence without changing the four JEP-Core verbs or their protocol positioning.

Added or corrected:

- strict UTF-8 JSON, duplicate-member, I-JSON, field-type, and verb-shape processing;
- complete RFC 8785 JCS in the Python Level 1 path and compatible ECMAScript processing in TypeScript;
- detached compact JWS/Ed25519 validation, JOSE `crit` handling, and JWK type/use checks;
- accurate highest-completed validation levels;
- acceptance freshness and persistent replay-cache handling;
- seed Level 3 chain checks with explicit observed-log assumptions;
- handler-backed critical-extension processing;
- exact manifest assertions for validity, error code, completed level, and selected event hashes;
- JCS number, UTF-16 key-order, and string vectors shared across Python and TypeScript;
- an explicit Level 0 boundary for the Go seed, with no ad-hoc event hash;
- CI for Python, TypeScript, Go, schemas, and the manifest-driven suite.

See `docs/IMPLEMENTATION-ALIGNMENT-0.6.1.md` for the boundary and rationale.

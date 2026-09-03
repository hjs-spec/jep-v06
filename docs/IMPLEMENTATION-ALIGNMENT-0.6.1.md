# JEP v0.6 Implementation Alignment Pass

This pass aligns executable repository artifacts with the validation boundaries declared by JEP-Core-0.6 and the companion conformance draft. It does not change J/D/T/V semantics.

## Corrected

- strict UTF-8 JSON and duplicate member rejection;
- interoperable JSON number and string checks;
- complete RFC 8785 canonicalization in the Python Level 1 path;
- RFC 8785-compatible ECMAScript canonicalization in the TypeScript Level 1 path;
- detached compact JWS processing and unsupported JOSE `crit` rejection;
- Ed25519 JWK type and usage checks;
- T target/scope and V verification-scope structural enforcement for object-form baseline events;
- validation results now report the highest stage actually completed;
- acceptance mode now requires replay state and checks freshness/future skew;
- seed chain validation now reports observed-log assumptions and performs reference, replay, termination-reuse, and cycle checks;
- critical extensions require a concrete handler, not only an identifier allowlist;
- manifest-driven tests now compare exact failure code, validation level, and selected event hashes;
- the Go seed no longer emits a non-RFC-8785 event hash or implies Level 1 capability.

## Boundaries retained

- JEP-Core does not determine legal liability, authorization validity, external truth, regulatory compliance, or complete-log availability.
- Local `kid-prefix` and `inline` bindings are test profiles, not global identity or trust standards.
- A successful seed chain check is not a causal or legal responsibility determination.
- A `V` event is not required by JEP-Core-0.6 to contain a generic `result` field; the repository therefore retains a valid V vector without `result`.

## Conformance evidence

The root `test-manifest.json` is the executable source of test expectations. Every negative vector identifies the exact failure code and completed validation level expected from the Python reference implementation. Cross-language JCS edge vectors are shared with the TypeScript seed.

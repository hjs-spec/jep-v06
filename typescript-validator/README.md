# JEP TypeScript Validator Seed

Minimal TypeScript/JavaScript structural validator for cross-language interoperability.

It computes JCS-compatible seed canonicalization and event hash, checks required fields,
detached JWS compact shape, and unknown critical extensions. It does not perform
Ed25519 verification without an additional runtime crypto dependency.

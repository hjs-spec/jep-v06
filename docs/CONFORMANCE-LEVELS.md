# JEP v0.6 Conformance Levels

JEP validation levels are cumulative. A result reports the highest stage actually completed; the level at which an error is classified is not automatically the completed level.

## Level 0 — Syntax

- strict UTF-8 JSON and I-JSON constraints;
- duplicate member rejection;
- required fields and field types;
- wire version, verb, digest, nonce, reference, extension, and verb-specific structural checks.

The Go validator’s explicit `syntax` mode stops here and returns no event hash. Its event and chain modes continue through the checks described below.

## Level 1 — Cryptographic

Level 0 plus:

- RFC 8785 JCS canonicalization;
- detached signature-container processing;
- signature algorithm and key-type checks;
- signature verification;
- full signed-event hash calculation.

A missing key, malformed signature, key-type mismatch, or failed signature does not complete Level 1.

## Level 2 — Actor binding

Level 1 plus successful evaluation of an explicitly named trust profile binding the signing key to `who`. The local `kid-prefix` and `inline` profiles are demonstration profiles only.

## Level 3 — Chain

Level 2 plus the declared chain checks, including applicable reference resolution, replay handling, termination effects, cycle detection, critical extension processing, and observed-log assumption reporting.

## Level 4 — Policy

Level 3 plus an explicitly named domain, organizational, legal, or regulatory policy profile. The core seed does not claim Level 4.

## Important boundaries

- A cryptographically valid event may be actor-binding or policy invalid.
- Archival validity is distinct from real-time acceptance.
- A successful reference-chain validation does not prove causality, external truth, complete logging, legal liability, or authorization validity.

The Go validator now implements the shared baseline, explicit local actor binding, chain checks, and persistent acceptance replay checks. Its `syntax` command remains an explicit Level-0-only mode. See `go-validator/README.md`.

# JEP v0.6 Conformance Levels

This document defines practical conformance levels for implementations.

These levels are non-normative labels built on top of the JEP validation model.

## Level A — Parse-only implementation

Supports:

- JSON parsing;
- duplicate member rejection;
- required field validation;
- verb validation;
- structural schema checks.

Does not require signature verification.

## Level B — Core cryptographic verifier

Supports Level A plus:

- JCS canonicalization;
- detached JWS verification;
- event hash calculation;
- algorithm-tagged digest handling;
- validation result object.

## Level C — Actor-binding verifier

Supports Level B plus:

- trust profile interface;
- `who` / `kid` binding;
- key rotation awareness;
- revocation handling where profile-defined;
- historical key validity where profile-defined.

## Level D — Chain verifier

Supports Level C plus:

- reference resolution;
- chain validation;
- termination effect checks;
- cycle detection;
- observed-log assumption reporting.

## Level E — Profile-aware verifier

Supports Level D plus one or more optional profiles:

- DID/VC;
- X.509;
- OAuth/OIDC;
- RATS;
- Local IAM;
- HJS Archive;
- JAC Chain;
- AI Actor.

## Declaration examples

```text
This implementation conforms to JEP-Core-0.6 Level B.

This implementation conforms to JEP-Core-0.6 Level D and supports
jep-profile:hjs-archive:0.

This implementation conforms to JEP-Core-0.6 Level E with DID/VC and
JAC Chain profiles.
```

## Important rule

A conformance level does not imply legal, factual, regulatory, or policy correctness unless the relevant external profile has been evaluated.

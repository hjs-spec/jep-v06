# JEP v0.6 Draft Set — Engineering-Complete Seed Pass

This package continues the v0.6 draft set and adds engineering artifacts
inside the same version.

## Included drafts

- `draft-wang-jep-judgment-event-protocol-06.md`
- `draft-wang-jep-profiles-00.md`
- `draft-wang-jep-conformance-00.md`

## Added in this pass

- Cross-document references between Core, Profiles, and Conformance.
- Signed Ed25519/JWS/JCS baseline vectors.
- Canonical unsigned payload fixture.
- Event hash fixture.
- Invalid signature vector.
- Reference hash mismatch vector.
- Unknown critical extension vector.
- Seed JSON Schemas:
  - `jep-event.schema.json`
  - `jep-validation-result.schema.json`
  - `jep-extension.schema.json`
  - `jep-profile.schema.json`
  - `jep-ref.schema.json`
  - `jep-signature.schema.json`
- Minimal Python reference validator:
  - `reference-validator/jep_validate.py`

## Signing vector generation

Cryptography available: True


The seed vectors are intended for interoperability bootstrapping.
They are not production credentials.


## Continued conformance-suite pass

Added:

- upgraded reference validator with subcommands:
  - `validate`
  - `validate-chain`
  - `run-tests`
- duplicate JSON member rejection support;
- test manifest;
- pytest smoke tests;
- GitHub Actions CI skeleton;
- Makefile;
- pyproject.toml;
- local validation report.


## Standards-format and expanded interop pass

Added:

- Internet-Draft style `.txt` renderings.
- Seed RFCXML `.xml` source files.
- Table of Contents in all three Markdown drafts.
- Normative and Informative References in all three drafts.
- More complete IANA Considerations.
- Profile-specific test vectors.
- TypeScript validator seed.
- Verb-specific JSON Schema constraints.
- Additional invalid cases:
  - duplicate member
  - nonce replay
  - terminated delegation reuse
  - extension conflict
  - algorithm downgrade
  - expired credential


## Direct v0.6 infrastructure upgrade pass

Added directly into v0.6:

- `docs/POSITIONING.md`
- `docs/IETF-SUBMISSION-CHECKLIST.md`
- `docs/ERROR-CODE-COVERAGE.md`
- expanded invalid cases for more error-code coverage;
- expanded DID/VC, HJS, and JAC profile vectors;
- synthetic DID document and VC examples;
- TypeScript validator with Ed25519 verification path using Node crypto;
- Go structural validator seed;
- regenerated IETF-style TXT and seed XML files;
- v0.6 direct upgrade note in all three drafts.


## Adoption and review guide pass

Added directly into v0.6:

- `docs/IMPLEMENTER-GUIDE.md`
- `docs/PROFILE-AUTHOR-GUIDE.md`
- `docs/SECURITY-REVIEW-NOTES.md`
- `docs/PRIVACY-REVIEW-NOTES.md`
- `docs/ONE-PAGE-OVERVIEW.md`
- `docs/END-TO-END-DEMO.md`
- `docs/CONFORMANCE-LEVELS.md`
- `docs/INTEROPERABILITY-REPORT-TEMPLATE.md`

These files do not change JEP-Core semantics. They improve implementability,
profile governance, review readiness, and ecosystem adoption.

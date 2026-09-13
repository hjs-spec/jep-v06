# JEP v0.6 Python Reference Validator

This validator targets JEP-Core-0.6 and the repository's `JEP-Baseline-Ed25519-JWS-JCS-0.6` conformance class.

Implemented stages:

- Level 0: strict UTF-8 JSON, duplicate-member rejection, I-JSON constraints, top-level and verb-specific structural checks.
- Level 1: RFC 8785 JCS, detached compact JWS/Ed25519 verification, and full signed-event hash calculation.
- Level 2: optional local demonstration profiles (`kid-prefix` and `inline`) for actor/key binding.
- Level 3: seed JSONL reference-chain processing, termination-reuse checks, replay checks, cycle detection, and observed-log reporting.

It is a conformance implementation, not a production key-management, evidence, authorization, policy, or legal-liability engine.

## Install

From the repository root:

```bash
python -m pip install -e '.[test]'
```

The Python implementation depends on `rfc8785==0.1.4`; ordinary `json.dumps(sort_keys=True)` is not a substitute for RFC 8785.

## Commands

```bash
python reference-validator/jep_validate.py validate \
  test-vectors/interop/control-J.json \
  --keys test-vectors/interop/public-keys.json

python reference-validator/jep_validate.py validate \
  test-vectors/interop/control-J.json \
  --keys test-vectors/interop/public-keys.json \
  --mode acceptance \
  --replay-cache .cache/jep-replay.json

python reference-validator/jep_validate.py validate-chain \
  test-vectors/valid/delegation-verification-termination-chain.jsonl \
  --keys test-vectors/valid/public-keys.json \
  --trust-profile kid-prefix \
  --log-assumption partial

python reference-validator/jep_validate.py run-tests test-manifest.json
```

Acceptance mode requires a persistent replay cache and applies configurable freshness and future-skew windows. Archival mode does not reject an event solely because its event timestamp is old.

Replay contexts use `v2:` followed by four UTF-8 byte-length-prefixed strings
(`length:value`): actor, audience (empty if absent), profile, and nonce. Python,
TypeScript, and Go use the same encoding, including for Unicode and control
characters. Existing delimiter-based entries remain effective and are preserved;
an ambiguous old entry still fails closed. Upgrade all consumers of a shared
cache together: older validators cannot recognize new entries. Keep the cache
through the freshness window; do not clear it to perform the upgrade.

Critical JEP extensions are accepted only when a concrete handler is implemented. Merely recognizing an extension identifier is not sufficient.

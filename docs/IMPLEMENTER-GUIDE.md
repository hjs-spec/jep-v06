# JEP v0.6 Implementer Guide

This guide describes the minimum implementation path for JEP-Core-0.6.

It is non-normative. The normative requirements remain in:

- `draft-wang-jep-judgment-event-protocol-06.md`
- `draft-wang-jep-profiles-00.md`
- `draft-wang-jep-conformance-00.md`

## 1. Minimum implementation path

A minimal JEP-Core verifier should implement the following steps:

```text
1. Parse JSON.
2. Reject duplicate JSON member names.
3. Validate required top-level fields.
4. Validate verb-specific requirements.
5. Remove `sig` to construct the unsigned event.
6. JCS-canonicalize the unsigned event.
7. Verify the detached JWS signature over the canonicalized payload.
8. Compute the event hash over the full signed event.
9. Resolve `who` and `kid` under a trust profile.
10. Process `ext` and `ext_crit`.
11. Return a structured validation result.
```

## 2. Minimal producer checklist

A JEP producer should:

- emit I-JSON-compatible JSON;
- set `jep` to `"1"`;
- use one of `J`, `D`, `T`, or `V`;
- generate a fresh nonce;
- include `who`, `when`, `what`, `aud`, `ref`, and `sig` as required;
- canonicalize the unsigned payload using JCS;
- sign using a conformance-supported detached JWS profile;
- include `ext_crit` only for extensions required for validation.

## 3. Minimal verifier checklist

A JEP verifier should:

- reject invalid JSON;
- reject duplicate JSON member names;
- reject unsupported JEP wire-format versions;
- reject unknown verbs;
- reject malformed or missing signatures;
- verify detached JWS;
- compute event hash;
- reject unknown critical extensions;
- distinguish validation level from policy validity.

## 4. Validation levels

Implementation should report the highest completed validation level:

| Level | Name | Meaning |
|---|---|---|
| 0 | Syntax | JSON and field shape |
| 1 | Cryptographic | Signature, canonicalization, hash |
| 2 | Actor Binding | Key-to-actor binding under trust profile |
| 3 | Chain | References, extension processing, termination effects |
| 4 | Policy | External policy, legal, regulatory, or domain logic |

Do not report Level 4 unless a policy profile was actually evaluated.

## 5. Common mistakes

Avoid these mistakes:

- treating signature validity as factual truth;
- treating `who` as necessarily identical to the signer;
- treating `ref` as causality;
- treating `aud` as access control;
- treating `V` as global fact verification;
- treating HJS archival presence as complete-log proof;
- treating JAC chain reconstruction as legal liability.

## 6. Suggested implementation stages

```text
Stage 1: Parser and schema checks
Stage 2: JCS + event hash
Stage 3: detached JWS verification
Stage 4: validation result object and error codes
Stage 5: critical extension handling
Stage 6: trust profile interface
Stage 7: chain validation
Stage 8: optional profiles
```

## 7. Test before publishing

Run:

```bash
python reference-validator/jep_validate.py validate test-vectors/valid/J-basic-signed.json --keys test-vectors/valid/public-keys.json
python reference-validator/jep_validate.py validate-chain test-vectors/valid/delegation-verification-termination-chain.jsonl --keys test-vectors/valid/public-keys.json
python reference-validator/jep_validate.py run-tests test-vectors --keys test-vectors/valid/public-keys.json
```

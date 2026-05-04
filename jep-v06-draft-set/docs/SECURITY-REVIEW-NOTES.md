# JEP v0.6 Security Review Notes

This document lists security review focus areas for JEP-Core, Profiles, and Conformance.

It is non-normative and intended for reviewers.

## 1. Core security boundary

A valid JEP event proves protocol-level integrity under an applicable trust profile.

It does not prove:

- external truth;
- legal liability;
- authorization validity;
- policy compliance;
- complete log availability;
- actor intent;
- model correctness.

## 2. Review checklist

Reviewers should examine:

```text
[ ] JCS canonicalization behavior
[ ] detached JWS signing input
[ ] event hash calculation
[ ] separation between signing input and event hash
[ ] duplicate JSON member rejection
[ ] unsupported algorithm rejection
[ ] prohibited algorithm rejection
[ ] key-to-actor binding
[ ] nonce replay handling
[ ] timestamp freshness handling
[ ] unknown critical extension rejection
[ ] extension conflict handling
[ ] reference hash mismatch handling
[ ] chain cycle handling
[ ] terminated delegation reuse handling
[ ] archival validation semantics
[ ] profile downgrade behavior
```

## 3. Threats

### Algorithm downgrade

A verifier must reject algorithms prohibited by the applicable profile.

### Actor/key misbinding

A valid signature is insufficient if the signing key is not bound to `who`.

### False verification

A V event must declare its verification scope. A V event does not verify beyond that scope.

### Log omission

A reference chain does not prove complete logging unless a complete-log profile is declared.

### Key compromise

JEP-Core does not define global revocation. Trust profiles must handle key rotation, revocation, and historical validation.

### Timestamp manipulation

`when` is actor-supplied. Stronger time evidence requires timestamping, receipt, archival, or transparency profiles.

### Unknown critical extension

Unknown critical extensions must cause rejection.

### Digest dictionary attack

Digest references may leak information if the underlying content has low entropy.

## 4. Security-sensitive failure codes

Security-sensitive failures include:

```text
ERR_SIGNATURE_INVALID
ERR_PROHIBITED_SIGNATURE_ALG
ERR_ALG_KEY_TYPE_MISMATCH
ERR_KEY_NOT_BOUND_TO_ACTOR
ERR_NONCE_REPLAY
ERR_REF_HASH_MISMATCH
ERR_UNKNOWN_CRITICAL_EXTENSION
ERR_TERMINATED_REFERENCE_REUSED
ERR_EXTENSION_CONFLICT
```

## 5. Red-team questions

- Can a verifier be tricked into treating Level 1 as Level 4?
- Can `ref` be misrepresented as causality?
- Can an attacker downgrade algorithm policy?
- Can a non-critical extension be used to smuggle critical semantics?
- Can a profile overclaim legal or factual conclusions?
- Can digest references be brute-forced?
- Can archived events be presented without disclosure of redaction?

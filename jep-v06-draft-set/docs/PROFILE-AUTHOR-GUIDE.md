# JEP v0.6 Profile Author Guide

This guide helps authors define optional JEP profiles without destabilizing JEP-Core.

Profiles are optional interoperability layers. They must not redefine Core semantics.

## 1. Profile boundary

A profile may define:

- actor identifier forms;
- key resolution;
- actor/key binding;
- credential rules;
- authorization context;
- attestation evidence;
- archival behavior;
- chain interpretation;
- policy hooks.

A profile must not redefine:

- J/D/T/V semantics;
- event hash semantics;
- signature semantics;
- validation levels;
- core failure-code semantics;
- `ext_crit` behavior;
- JEP-Core conformance.

## 2. Required profile metadata

Each profile should declare:

```text
profile_id:
profile_name:
profile_version:
supported_jep_core:
status:
change_controller:
```

Example:

```text
profile_id: jep-profile:did-vc:0
profile_name: JEP DID/VC Profile
profile_version: 0
supported_jep_core: JEP-Core-0.6
status: optional experimental
```

## 3. Required profile sections

A profile should include:

1. Scope
2. Non-goals
3. Actor identifier forms
4. Key resolution
5. Actor/key binding
6. Algorithm policy
7. Credential or attestation handling
8. Validation-level impact
9. Failure-code mapping
10. Security considerations
11. Privacy considerations
12. Test vectors
13. Conformance class, if any

## 4. Validation-level impact

A profile must say which validation level it affects.

Examples:

| Profile feature | Likely validation level |
|---|---|
| DID key binding | Level 2 |
| X.509 certificate chain | Level 2 |
| VC role credential | Level 2 or Level 4 |
| OAuth authorization context | Level 4 |
| RATS attestation | Level 4 |
| HJS archive receipt | Level 3 |
| JAC chain reconstruction | Level 3 |

## 5. Failure-code mapping

A profile should map failures to existing JEP codes where possible.

Examples:

```text
DID document unavailable -> ERR_ACTOR_UNRESOLVED
key not in verificationMethod -> ERR_KEY_NOT_BOUND_TO_ACTOR
credential expired -> ERR_POLICY_REJECTED
unknown required profile extension -> ERR_UNKNOWN_CRITICAL_EXTENSION
attestation evidence missing -> ERR_DOMAIN_REQUIREMENT_UNSATISFIED
```

## 6. Security requirements

A profile must consider:

- actor misbinding;
- key substitution;
- credential overclaim;
- algorithm downgrade;
- profile downgrade;
- replay or stale evidence;
- issuer trust;
- external evidence tampering.

## 7. Privacy requirements

A profile must consider:

- identifier linkability;
- credential disclosure;
- workflow leakage;
- digest dictionary attacks;
- cross-context correlation;
- retention and redaction;
- selective disclosure.

## 8. Profile registration template

```text
Profile identifier:
Profile name:
Version:
Supported JEP-Core version:
Description:
Actor identifier forms:
Key resolution:
Algorithm policy:
Credential/attestation dependencies:
Validation-level impact:
Failure-code mapping:
Security considerations:
Privacy considerations:
Reference implementation:
Test vectors:
Change controller:
```

## 9. Profile authoring rule

When in doubt, keep the profile optional and do not change JEP-Core.

# JEP v0.6 One-Page Overview

## What JEP is

JEP is a neutral, signed, verifiable event protocol for judgment-related acts in human, organizational, software, and AI-agent systems.

JEP defines four event verbs:

| Verb | Name | Meaning |
|---|---|---|
| J | Judgment | An actor made or endorsed a decision-related claim |
| D | Delegation | An actor delegated a task, authority, capability, or context |
| T | Termination | An actor terminated a delegation, authority, context, or reliance |
| V | Verification | An actor verified something within a declared scope |

## Three-document structure

```text
JEP-Core -06
  Stable narrow-waist event protocol.

JEP-Profiles -00
  Optional interoperability profiles.

JEP-Conformance -00
  Schemas, test vectors, validators, and conformance classes.
```

## Core principle

```text
signature valid ≠ claim true ≠ legal liability ≠ policy compliance
```

## JEP / HJS / JAC

```text
JEP = atomic signed judgment events
HJS = archival, privacy, evidence lifecycle
JAC = causality and accountability chains
```

## What JEP does not replace

JEP does not replace:

- DID;
- VC;
- OAuth;
- X.509;
- RATS;
- blockchain;
- HJS;
- JAC;
- AI agent frameworks;
- legal or regulatory systems.

## Minimal event shape

```json
{
  "jep": "1",
  "verb": "J",
  "who": "did:example:agent-789",
  "when": 1742345678,
  "what": "sha256:...",
  "nonce": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "aud": "https://platform.example.com",
  "ref": null,
  "sig": "..."
}
```

## Why v0.6 matters

v0.6 turns JEP from a compact event draft into a structured infrastructure set:

- stable Core;
- optional Profiles;
- runnable Conformance seed;
- signed test vectors;
- Python / TypeScript / Go validator seeds;
- security and privacy boundaries;
- IETF-style rendered files.

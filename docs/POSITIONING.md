# JEP v0.6 Positioning

JEP is the neutral event layer for verifiable judgment acts.

## What JEP is

JEP defines a minimal, signed, verifiable event protocol for judgment-related acts:

- J — Judgment
- D — Delegation
- T — Termination
- V — Verification

JEP records protocol-level facts about signed events, references, validation levels, and extension processing.

## What JEP is not

JEP is not a DID replacement.

JEP is not a VC replacement.

JEP is not a legal liability engine.

JEP is not a regulatory compliance engine.

JEP is not a blockchain protocol.

JEP is not an AI agent framework.

JEP is not a storage or archival system.

JEP is not HJS.

JEP is not JAC.

## Relationship to adjacent layers

DID, VC, X.509, OAuth/OIDC, RATS, Local IAM, blockchain anchoring, and AI actor identity systems are optional profiles.

HJS-like systems manage archival, privacy, redaction, receipt, retention, and evidence lifecycle for JEP events.

JAC-like systems compose JEP events into causality chains, responsibility chains, delegation paths, verification paths, and workflow accountability graphs.

## Narrow-waist principle

JEP-Core stays narrow:

```text
signed event + verb + actor + time + claim + nonce + audience + reference + extension + signature + validation result
```

Everything else is expressed by optional profiles, extensions, policy layers, archival layers, or chain-composition layers.

## Core boundary

A valid JEP event proves that an event payload was processed under JEP validation rules.

It does not by itself prove:

- external truth;
- legal liability;
- moral responsibility;
- authorization validity;
- regulatory compliance;
- complete log availability;
- human understanding;
- model correctness.

## Infrastructure positioning

JEP v0.6 is designed as a neutral narrow-waist event infrastructure for human, organizational, software, and AI-agent systems.

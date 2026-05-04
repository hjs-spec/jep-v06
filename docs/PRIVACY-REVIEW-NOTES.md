# JEP v0.6 Privacy Review Notes

This document lists privacy review considerations for JEP deployments.

JEP is an accountability event protocol component. It should not become a general monitoring protocol.

## 1. Privacy boundary

JEP events can reveal:

- actor identity;
- subject identity;
- timestamp and workflow timing;
- delegation relationships;
- verification relationships;
- tool usage;
- organizational structure;
- model or agent participation;
- evidence references.

Deployers should minimize what is embedded directly in events.

## 2. Data minimization

Use digest references instead of raw evidence when possible.

Prefer:

```text
what.evidence_ref = sha256:...
```

over embedding sensitive evidence.

## 3. Digest reference risks

Digest references can still leak information through:

- confirmation attacks;
- dictionary attacks;
- cross-log correlation;
- repeated identifier hashing.

Mitigations include:

- salted digest;
- domain-separated digest;
- commitment scheme;
- access-controlled evidence store;
- audience-bound reference;
- selective disclosure;
- redacted evidence.

## 4. Audience and access control

`aud` identifies intended audience or validation context. It is not access control.

Access control belongs to deployment policy, HJS-like archival systems, or external storage systems.

## 5. HJS boundary

HJS-like systems may provide:

- redaction;
- retention policy;
- selective disclosure;
- receipt records;
- archive-time metadata;
- evidence custody;
- privacy policy enforcement.

JEP-Core does not define these mechanisms.

## 6. Human-in-the-loop privacy

Human review events may reveal reviewer identity, role, timing, and workflow structure.

Deployments should consider pseudonymous reviewer identifiers or role-based identifiers when appropriate.

## 7. AI actor privacy

AI actor identifiers may reveal model, vendor, tool, workflow, or deployment environment.

Profiles should define how much identity detail is required.

## 8. Privacy checklist

```text
[ ] Is raw sensitive data embedded in `what`?
[ ] Can evidence be referenced by digest instead?
[ ] Is the digest vulnerable to dictionary attack?
[ ] Is `aud` used correctly?
[ ] Are actor identifiers linkable across contexts?
[ ] Is retention policy defined outside JEP-Core?
[ ] Is redaction policy defined?
[ ] Is selective disclosure possible?
[ ] Are archive and receipt times separated from event time?
```

# JEP v0.6 End-to-End Demo

This demo shows how JEP, HJS, and JAC can work together without crossing boundaries.

## Scenario

A human delegates a document-summary task to an agent. The agent produces a judgment. A verifier validates the judgment. The human terminates the delegation. HJS archives evidence. JAC reconstructs the accountability chain.

## Step 1 — Human delegates to agent

Event type: `D`

```text
Human -> Agent
scope: summarize-document
constraint: no external send
```

Test vector:

```text
test-vectors/valid/D-basic-signed.json
```

## Step 2 — Agent makes judgment

Event type: `J`

```text
Agent -> Judgment
claim: document summary output digest
```

Test vector:

```text
test-vectors/valid/J-basic-signed.json
```

## Step 3 — Verifier verifies judgment

Event type: `V`

```text
Verifier -> J event
scope: syntax, cryptographic, actor_binding
```

Test vector:

```text
test-vectors/valid/V-basic-signed.json
```

## Step 4 — Human terminates delegation

Event type: `T`

```text
Human -> D event
termination_scope: delegation
```

Test vector:

```text
test-vectors/valid/T-basic-signed.json
```

## Step 5 — HJS archives/redacts evidence

HJS handles:

- receipt time;
- archive time;
- redaction manifest;
- retention policy;
- evidence lifecycle.

Test vector:

```text
test-vectors/profiles/hjs-redacted-archive-example.json
```

## Step 6 — JAC reconstructs chain

JAC interprets causal/accountability edges over JEP events.

Test vector:

```text
test-vectors/profiles/jac-causal-chain-expanded.json
```

## Run validation

```bash
python reference-validator/jep_validate.py validate-chain test-vectors/valid/delegation-verification-termination-chain.jsonl --keys test-vectors/valid/public-keys.json
```

## Boundary statement

JEP verifies event integrity and protocol facts.

HJS manages archival and privacy lifecycle.

JAC composes events into causal and accountability structures.

None of these layers alone determines legal liability or external truth.

# JEP-TSTO Binding/01: declared validation path

Binding/01 is an independent experimental binding to TSTO/00. It leaves JEP-Core 0.6 and wire version `jep: "1"` unchanged.

The [Binding/01 English specification](https://github.com/cognitive-emergence/tsto-spec/blob/main/bindings/JEP-TSTO-Binding-01.md) and its supplementary Schema define a stricter event subset. They do not redefine every object reference, constraint, or termination claim permitted by generic JEP-Core.

## Text, Schema, and validator relationship

Core Sections 7.5, 7.8, and 8 give general event semantics. The minimal Schema shown in conformance Section 4.1 is illustrative and deliberately broader than the shipped `schemas/jep-event.schema.json`. The shipped Schema additionally requires typed object references with `type,value`, array-valued object-claim constraints, and a Termination claim with `target`.

Binding/01 chooses this existing shipped subset:

| Event | Carrier |
| --- | --- |
| J/D/V | Exact `ref = {"type":"TargetStateTransition","value":TSTORef}`; TSTORef retains its exact five members. |
| D | Optional `what.constraints` is an array of constraint objects; all apply. |
| T | `ref` is the target JEP event hash, `what.target` equals that hash, and `what.subject` is the affected TSTORef. |
| All | Signed `ext["jep-tsto.binding"].id` identifies the published 01 Schema. |

Use the shipped JEP Schema AND the Binding/01 Schema on the same signed event. Then apply signature/trust checks, exact TSTO id+digest resolution, T target equality and resolution, and applicable domain-policy evaluation. Standard JSON Schema cannot compare arbitrary `target` and `ref` values or evaluate signatures and evidence.

The Python, TypeScript, and Go seed validators are bootstrap artifacts with differing coverage. None alone is declared a complete Binding/01 validator. In particular, the Python seed canonicalizer is sufficient for its seed domain, not every RFC 8785 input; its signature verifier accepts the baseline JOSE `Ed25519` label. The supported composite path uses the Binding harness's complete RFC 8785 implementation and two Schemas before independent checks. The ASCII/integer baseline signed events are additionally checked with the unchanged Python seed, over the exact same events.

## Algorithm and trust boundary

The baseline class in conformance Section 2.6 uses JOSE `alg: Ed25519`. Prooftask's authenticated-recorder profile uses `alg: EdDSA` and an Ed25519 key. These are separately selected profiles, not interchangeable labels. A signed header MUST NOT be rewritten. Passing the recorder profile does not claim that the Ed25519-only Python seed accepts it.

The public harness declares synthetic test actor/key trust. It checks cryptography, exact object resolution, policy-reference equality and target-event integrity. It does not establish real-world actor authority, legal effect, factual truth, complete TSTO policy evaluation, production replay prevention, or payment validity. Those obligations still belong to the claimed role and deployment profile.

## Reproduce

Check out the published Binding/01 source in a sibling `tsto-spec` directory, install its declared Python requirements, and run:

```sh
python ../tsto-spec/scripts/check-binding-01.py \
  --jep-seed reference-validator/jep_validate.py
```

Expected: 8 signed events pass the composite path under their respective algorithms; 15 hostile cases fail; 4 original Binding/00 Schema incompatibilities are reproduced; 4 Ed25519 baseline events also pass this repository's Python seed, while an EdDSA event is rejected by that seed.

## Historical compatibility

Binding/00, Prooftask candidate.1, and published 01 are distinct signed identities. Historical compatibility decoding preserves bytes and hashes. It does not convert old records into current joint-Schema conformance. Unknown/mixed markers and failed version validation MUST NOT trigger silent fallback. No JEP-Core text, shipped Schema, baseline algorithm, or seed validator is changed by this integration note.

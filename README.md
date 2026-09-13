# JEP v0.6 Draft Set

This repository contains the JEP-Core `-06` working draft, optional profile bindings, and the companion conformance seed.

## Public mirrors

- Hugging Face Space: https://huggingface.co/spaces/yuqiangJEP/jep-v06-spec-demo/tree/main
- Hugging Face Conformance Dataset: https://huggingface.co/datasets/yuqiangJEP/jep-v06-conformance-suite
- IETF JEP-Core Draft: https://datatracker.ietf.org/doc/draft-wang-jep-judgment-event-protocol/
- IETF JEP-Conformance Draft: https://datatracker.ietf.org/doc/draft-wang-jep-conformance/
- IETF JEP-Profiles Draft: https://datatracker.ietf.org/doc/draft-wang-jep-profiles/

## Drafts

1. `draft-wang-jep-judgment-event-protocol-06.md` — the neutral J/D/T/V event core.
2. `draft-wang-jep-profiles-00.md` — optional trust and interoperability profiles.
3. `draft-wang-jep-conformance-00.md` — conformance classes, schemas, vectors, and validator behavior.

The Internet-Drafts are normative for this package. The schemas and validators are executable conformance aids; they do not make legal, policy, factual, or external-target determinations.

## Conformance implementations

| Implementation | Declared boundary |
|---|---|
| `reference-validator/` | Python Level 0/1 baseline, optional local Level 2 binding, and seed Level 3 chain checks |
| `typescript-validator/` | TypeScript Level 0/1 baseline plus optional local binding and acceptance replay/freshness checks |
| `go-validator/` | Explicit Level 0 syntax verifier seed only; it does not claim signature verification or event hashing |

The Python and TypeScript Level 1 paths use RFC 8785 JCS and detached compact JWS/Ed25519 processing for the repository baseline. A validator reports only the highest validation level it actually completed.

## Run

```bash
python -m pip install -e '.[test]'
make test
make conformance
make go
```

For TypeScript:

```bash
cd typescript-validator
npm install
npm run check
```

The manifest-driven suite checks exact validity, failure code, completed level, and selected event hashes. It must not treat an unrelated early failure as success for a later-stage test.

## Scope discipline

This alignment pass does not change JEP's four verbs or expand JEP-Core into a legal-liability, authorization, policy, or external-truth engine. Profile-specific bindings remain outside the core.

## Guides

Additional implementation and review guidance is under `docs/`.
- `IMPLEMENTER-GUIDE.md`
- `PROFILE-AUTHOR-GUIDE.md`
- `SECURITY-REVIEW-NOTES.md`
- `PRIVACY-REVIEW-NOTES.md`
- `ONE-PAGE-OVERVIEW.md`
- `END-TO-END-DEMO.md`
- `CONFORMANCE-LEVELS.md`
- `INTEROPERABILITY-REPORT-TEMPLATE.md`

## JEP-TSTO Binding/01

The [Binding/01 integration note](docs/JEP-TSTO-BINDING-01.md) declares the joint Schema, signature and immutable-reference validation path, historical compatibility, and algorithm boundaries without changing JEP-Core 0.6.

## Runtime and verification notes

See [HARDENING.md](HARDENING.md) for supported behavior, regression checks, and compatibility boundaries.

[Cross-repository hardening review map and verification evidence](docs/ECOSYSTEM-HARDENING-2026-09.md).

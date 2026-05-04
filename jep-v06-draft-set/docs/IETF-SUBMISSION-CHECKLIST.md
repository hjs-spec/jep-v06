# IETF Submission Checklist for JEP v0.6

## Primary upload order

1. `draft-wang-jep-judgment-event-protocol-06`
2. `draft-wang-jep-profiles-00`
3. `draft-wang-jep-conformance-00`

## Files to review before upload

- `ietf-rendered/draft-wang-jep-judgment-event-protocol-06.txt`
- `ietf-rendered/draft-wang-jep-judgment-event-protocol-06.xml`
- `ietf-rendered/draft-wang-jep-profiles-00.txt`
- `ietf-rendered/draft-wang-jep-profiles-00.xml`
- `ietf-rendered/draft-wang-jep-conformance-00.txt`
- `ietf-rendered/draft-wang-jep-conformance-00.xml`

## Required checks

- [ ] Confirm author metadata.
- [ ] Confirm intended status: Experimental.
- [ ] Confirm references are split into normative and informative.
- [ ] Confirm IANA considerations are present.
- [ ] Confirm security considerations are present.
- [ ] Confirm privacy considerations are present.
- [ ] Confirm no optional profile is required for JEP-Core conformance.
- [ ] Confirm `jep: "1"` is described as wire-format version.
- [ ] Confirm `JEP-Core-0.6` is described as specification release version.
- [ ] Confirm HJS and JAC are companion profiles, not replacements.
- [ ] Run local conformance seed.

## Local commands

```bash
python reference-validator/jep_validate.py validate test-vectors/valid/J-basic-signed.json --keys test-vectors/valid/public-keys.json
python reference-validator/jep_validate.py validate-chain test-vectors/valid/delegation-verification-termination-chain.jsonl --keys test-vectors/valid/public-keys.json
python reference-validator/jep_validate.py run-tests test-vectors --keys test-vectors/valid/public-keys.json
```

## Suggested public release assets

- three draft Markdown files;
- three rendered TXT files;
- seed RFCXML files;
- `schemas/`;
- `test-vectors/`;
- `reference-validator/`;
- `typescript-validator/`;
- `docs/POSITIONING.md`;
- `RELEASE-NOTES-v0.6.md`.

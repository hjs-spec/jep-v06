# JEP Reference Validator

Minimal baseline validator for JEP v0.6.

## Usage

```bash
python jep_validate.py validate ../test-vectors/valid/J-basic-signed.json --keys ../test-vectors/valid/public-keys.json
python jep_validate.py validate-chain ../test-vectors/valid/delegation-verification-termination-chain.jsonl --keys ../test-vectors/valid/public-keys.json
python jep_validate.py run-tests ../test-vectors --keys ../test-vectors/valid/public-keys.json
```

This validator is a conformance bootstrap tool, not a production security library.

PYTHON ?= python

.PHONY: validate test conformance zip

validate:
	$(PYTHON) reference-validator/jep_validate.py validate test-vectors/valid/J-basic-signed.json --keys test-vectors/valid/public-keys.json
	$(PYTHON) reference-validator/jep_validate.py validate-chain test-vectors/valid/delegation-verification-termination-chain.jsonl --keys test-vectors/valid/public-keys.json

test:
	$(PYTHON) -m pytest -q

conformance:
	$(PYTHON) reference-validator/jep_validate.py run-tests test-vectors --keys test-vectors/valid/public-keys.json

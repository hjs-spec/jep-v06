PYTHON ?= python
NPM ?= npm
GO ?= go

.PHONY: validate test conformance typescript go all

validate:
	$(PYTHON) reference-validator/jep_validate.py validate test-vectors/interop/control-J.json --keys test-vectors/interop/public-keys.json
	$(PYTHON) reference-validator/jep_validate.py validate-chain test-vectors/valid/delegation-verification-termination-chain.jsonl --keys test-vectors/valid/public-keys.json --trust-profile kid-prefix

conformance:
	$(PYTHON) reference-validator/jep_validate.py run-tests test-manifest.json

test:
	$(PYTHON) -m pytest

typescript:
	cd typescript-validator && $(NPM) install && $(NPM) run check

go:
	cd go-validator && $(GO) test ./...

all: test conformance go

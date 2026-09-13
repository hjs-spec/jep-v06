# JEP v0.6 TypeScript Validator Seed

The TypeScript seed implements strict JSON duplicate-member detection, I-JSON checks, the repository baseline event shape, RFC 8785-compatible ECMAScript canonicalization, detached compact JWS/Ed25519 verification, event hashes, critical-extension rejection, optional local actor binding, and acceptance replay/freshness checks.

It currently declares Level 0/1 capability plus optional local Level 2 actor binding. It does not declare JEP-Chain-0.6 conformance.

```bash
npm install
npm run check
```

Direct validation:

```bash
node dist/jep_validate.js \
  ../test-vectors/interop/control-J.json \
  ../test-vectors/interop/public-keys.json
```

The test script checks the same JCS edge vectors, exact failure codes, validation levels, and replay behavior used by the Python implementation.

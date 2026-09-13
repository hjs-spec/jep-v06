# JEP v0.6 Go Syntax Verifier Seed

This directory deliberately exposes an honest Level 0 boundary.

It validates:

- JSON shape and duplicate member rejection;
- interoperable JSON number constraints;
- core fields and J/D/T/V baseline structures;
- digest, nonce, reference, extension, and signature-container field shapes.

It does **not** perform RFC 8785 canonicalization, event hashing, key resolution, detached JWS verification, actor binding, replay processing, chain validation, or policy validation. Therefore it returns `event_hash: null` and never claims Level 1.

```bash
go test ./...
go run . ../test-vectors/interop/control-J.json
```

A future Go Level 1 implementation must use a complete RFC 8785 implementation and real Ed25519/JWS verification rather than the former ad-hoc key sorting routine.

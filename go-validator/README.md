# Go JEP-Core-0.6 validator

Independent RFC 8785 / detached JWS Ed25519 verifier. It passes the shared manifest used by Python and TypeScript; it does not invoke either runtime.

```sh
go install github.com/hjs-spec/jep-v06/go-validator@v0.7.0
go-validator validate event.json --keys keys.json
go-validator validate-chain chain.jsonl --keys keys.json --trust-profile kid-prefix
go-validator validate event.json --keys keys.json --mode acceptance --aud my-service --replay-cache nonces.json
```

Build locally with `go build -o jep-validate .`. `syntax file.json` explicitly runs only Level 0. `canonicalize file.json` emits RFC 8785 bytes. `validate` defaults to archival signature verification (Level 1); optional explicit `inline` or `kid-prefix` local trust profiles add actor binding (Level 2). Chain validation completes Level 3 only when actor binding also completed. No external policy or business truth is inferred.

Use locally configured trusted JWK files (map or JWKS). No remote key URLs from untrusted events are fetched. Malformed JOSE, duplicate JSON, noncanonical base64url and small-order identity forgeries fail closed.

Acceptance uses the same cache file and exclusive `.consume-lock` directory as the Python/TypeScript implementations. Locks left by a crash fail closed; remove only after confirming the owner is gone. Keep the cache throughout the freshness window. This CLI cache is for a shared local filesystem; use the API PostgreSQL backend for independent hosts.

CLI exit codes: 0 valid, 1 validation failure, 2 usage/file/key configuration error.

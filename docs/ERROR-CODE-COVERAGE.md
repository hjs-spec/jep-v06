# JEP v0.6 Error Code Coverage Matrix

The executable source of expectations is the root `test-manifest.json`. A negative vector passes only when the expected validity, exact error code, and completed validation level all match.

| Error code | Executed seed vector |
|---|---|
| `ERR_DUPLICATE_MEMBER` | `test-vectors/interop/duplicate-member.json` |
| `ERR_UNSUPPORTED_JEP_VERSION` | existing seed vector; structural coverage retained |
| `ERR_UNKNOWN_VERB` | `test-vectors/interop/unknown-verb.json` |
| `ERR_MISSING_REQUIRED_FIELD` | missing J `what`, T target/scope, and V `what`/scope vectors |
| `ERR_INVALID_FIELD_TYPE` | invalid actor, nonce, and empty claim-object vectors |
| `ERR_INVALID_TIMESTAMP` | `test-vectors/interop/invalid-when-string.json` |
| `ERR_SIGNATURE_CONTAINER_INVALID` | unsupported JOSE critical-header vector |
| `ERR_SIGNATURE_INVALID` | `test-vectors/interop/invalid-signature-control.json` |
| `ERR_KEY_UNRESOLVED` | `test-vectors/interop/key-not-found-level.json` |
| `ERR_ALG_KEY_TYPE_MISMATCH` | `test-vectors/interop/key-type-mismatch.json` |
| `ERR_UNKNOWN_CRITICAL_EXTENSION` | `test-vectors/interop/JEP-unknown-critical-level.json` |
| `ERR_EXTENSION_SCHEMA_INVALID` | critical-extension value absent vector |
| `ERR_NONCE_REPLAY` | stateful acceptance-mode pytest and TypeScript test |
| `ERR_REF_UNRESOLVED` | manifest fault-isolation regression plus chain resolver paths |
| `ERR_TERMINATED_REFERENCE_REUSED` | chain verifier logic; dedicated signed chain mutation remains an expansion item |
| `ERR_CYCLE_DETECTED` | chain verifier logic; dedicated signed cycle fixture remains an expansion item |

Profile-specific errors such as regulatory policy rejection or expired credentials are not claimed by the core baseline suite unless the relevant external profile is actually evaluated.

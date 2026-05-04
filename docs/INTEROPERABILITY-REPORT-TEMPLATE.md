# JEP v0.6 Interoperability Report Template

Use this template to publish implementation interoperability results.

```json
{
  "implementation": "example-jep-validator",
  "version": "0.1.0",
  "language": "Python",
  "jep_core": "0.6",
  "wire_format": "1",
  "conformance_level": "Level B",
  "conformance_classes": [
    "JEP-Core-0.6 Verifier",
    "JEP-Baseline-Ed25519-JWS-JCS-0.6"
  ],
  "profiles": [
    "jep-profile:did-vc:0"
  ],
  "supported_algorithms": [
    "Ed25519"
  ],
  "supported_hashes": [
    "sha256"
  ],
  "supported_validation_modes": [
    "acceptance",
    "archival"
  ],
  "supported_error_codes": [
    "ERR_SIGNATURE_INVALID",
    "ERR_UNKNOWN_CRITICAL_EXTENSION"
  ],
  "tests": {
    "suite": "jep-v0.6-conformance-seed",
    "passed": 0,
    "failed": 0,
    "skipped": 0
  },
  "notes": "Describe limitations, unsupported profiles, and known issues.",
  "date": "2026-05-04"
}
```

## Suggested report sections

1. Implementation identity
2. Supported JEP-Core version
3. Supported wire-format version
4. Supported conformance level
5. Supported algorithms
6. Supported profiles
7. Test-vector results
8. Known limitations
9. Security notes
10. Privacy notes

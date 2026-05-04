#!/usr/bin/env python3
"""
JEP v0.6 reference validator.

Scope:
- JSON parsing with duplicate member rejection
- core field validation
- JCS-compatible canonicalization for seed vectors
- detached JWS Compact Ed25519 verification
- event hash calculation
- unknown critical extension rejection
- simple reference hash lookup for chain files
- test-vector runner

This is a conformance bootstrap validator, not a production security library.
"""

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:
    Ed25519PublicKey = None

KNOWN_EXTENSIONS = {
    "https://jep.org/priv/digest-only",
    "https://jep.org/multisig",
    "https://jep.org/ttl",
    "https://jep.org/storage",
    "https://jep.org/subject",
    "https://jep.org/crypto/profile",
}

REQUIRED_FIELDS = ["jep", "verb", "who", "when", "nonce", "sig"]
VERBS = {"J", "D", "T", "V"}


class DuplicateKeyError(ValueError):
    pass


def no_duplicates_object_pairs_hook(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicateKeyError(f"Duplicate JSON member: {key}")
        obj[key] = value
    return obj


def load_json_no_duplicates(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=no_duplicates_object_pairs_hook)
    except DuplicateKeyError:
        raise
    except Exception as e:
        raise ValueError(f"Invalid JSON: {e}")


def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def jcs(obj):
    # This is sufficient for the seed vectors; production implementations
    # should use a complete RFC 8785 JCS implementation.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def err(code, message, level=0, recoverable=False, evidence=None):
    out = {"code": code, "message": message, "level": level, "recoverable": recoverable}
    if evidence:
        out["evidence"] = evidence
    return out


def validation_result(valid, level, mode, profile, event_hash=None, errors=None, warnings=None, scopes=None):
    return {
        "valid": valid,
        "level": level,
        "mode": mode,
        "profile": profile,
        "scopes": scopes or [],
        "event_hash": event_hash,
        "warnings": warnings or [],
        "errors": errors or [],
    }


def load_keys(path):
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        # Accept map of logical names to JWKs or direct kid->JWK maps.
        out = {}
        for k, v in data.items():
            if isinstance(v, dict) and "kid" in v:
                out[v["kid"]] = v
            elif isinstance(v, dict) and "x" in v:
                out[k] = v
        return out
    return {}


def event_hash(event):
    return "sha256:" + hashlib.sha256(jcs(event)).hexdigest()


def verify_detached_jws(event, payload, keys):
    sig = event.get("sig")
    if not isinstance(sig, str) or sig.count(".") != 2:
        return False, err("ERR_SIGNATURE_CONTAINER_INVALID", "sig is not detached JWS Compact Serialization", 1)
    protected_b64, empty, signature_b64 = sig.split(".")
    if empty != "":
        return False, err("ERR_SIGNATURE_CONTAINER_INVALID", "JWS payload segment must be empty for detached compact serialization", 1)
    try:
        protected = json.loads(b64u_decode(protected_b64))
    except Exception as e:
        return False, err("ERR_SIGNATURE_CONTAINER_INVALID", f"Invalid JWS protected header: {e}", 1)

    alg = protected.get("alg")
    kid = protected.get("kid")
    if alg != "Ed25519":
        return False, err("ERR_UNSUPPORTED_SIGNATURE_ALG", f"Unsupported alg: {alg}", 1)
    if Ed25519PublicKey is None:
        return False, err("ERR_SIGNATURE_INVALID", "cryptography package not available", 1)
    jwk = keys.get(kid)
    if not jwk:
        return False, err("ERR_KEY_UNRESOLVED", f"No public key for kid: {kid}", 2)
    try:
        raw = b64u_decode(jwk["x"])
        pk = Ed25519PublicKey.from_public_bytes(raw)
        signing_input = (protected_b64 + "." + b64u(payload)).encode("ascii")
        pk.verify(b64u_decode(signature_b64), signing_input)
        return True, None
    except Exception as e:
        return False, err("ERR_SIGNATURE_INVALID", str(e), 1)


def validate_event_obj(event, mode="archival", keys=None, known_hashes=None, expected_audience=None):
    keys = keys or {}
    known_hashes = known_hashes or {}

    for field in REQUIRED_FIELDS:
        if field not in event:
            return validation_result(False, 0, mode, "jep-core-0.6", errors=[
                err("ERR_MISSING_REQUIRED_FIELD", f"Missing {field}", 0)
            ])

    if event.get("jep") != "1":
        return validation_result(False, 0, mode, "jep-core-0.6", errors=[
            err("ERR_UNSUPPORTED_JEP_VERSION", "jep must be '1'", 0)
        ])

    if event.get("verb") not in VERBS:
        return validation_result(False, 0, mode, "jep-core-0.6", errors=[
            err("ERR_UNKNOWN_VERB", "verb must be J/D/T/V", 0)
        ])

    if event.get("verb") == "V" and event.get("ref") in (None, ""):
        return validation_result(False, 0, mode, "jep-core-0.6", errors=[
            err("ERR_MISSING_REQUIRED_FIELD", "V events require ref", 0)
        ])

    if event.get("verb") in {"J", "D", "T"} and "what" not in event:
        return validation_result(False, 0, mode, "jep-core-0.6", errors=[
            err("ERR_MISSING_REQUIRED_FIELD", f"{event.get('verb')} events require what", 0)
        ])

    unsigned = {k: v for k, v in event.items() if k != "sig"}
    payload = jcs(unsigned)
    ehash = event_hash(event)

    ok, e = verify_detached_jws(event, payload, keys)
    if not ok:
        level = e.get("level", 1)
        return validation_result(False, max(0, level - 1), mode, "jep-core-0.6", event_hash=ehash, errors=[e], scopes=["syntax"])

    # Basic audience check for acceptance mode when expected audience is provided.
    if mode == "acceptance" and expected_audience is not None and event.get("aud") != expected_audience:
        return validation_result(False, 1, mode, "jep-core-0.6", event_hash=ehash, errors=[
            err("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "aud does not match expected audience", 4)
        ], scopes=["syntax", "cryptographic"])

    for ext_id in event.get("ext_crit", []) or []:
        if ext_id not in KNOWN_EXTENSIONS:
            return validation_result(False, 2, mode, "jep-core-0.6", event_hash=ehash, errors=[
                err("ERR_UNKNOWN_CRITICAL_EXTENSION", f"Unknown critical extension: {ext_id}", 3)
            ], scopes=["syntax", "cryptographic"])

    ref = event.get("ref")
    if isinstance(ref, str) and ref.startswith("sha256:") and known_hashes:
        if ref not in known_hashes:
            return validation_result(False, 2, mode, "jep-core-0.6", event_hash=ehash, errors=[
                err("ERR_REF_UNRESOLVED", f"Referenced event hash not found: {ref}", 3)
            ], scopes=["syntax", "cryptographic"])

    return validation_result(True, 1, mode, "jep-core-0.6", event_hash=ehash, scopes=["syntax", "cryptographic"])


def validate_event_file(path, mode="archival", keys=None, expected_audience=None):
    try:
        data = load_json_no_duplicates(path)
    except DuplicateKeyError as e:
        return validation_result(False, 0, mode, "jep-core-0.6", errors=[err("ERR_DUPLICATE_MEMBER", str(e), 0)])
    except Exception as e:
        return validation_result(False, 0, mode, "jep-core-0.6", errors=[err("ERR_INVALID_JSON", str(e), 0)])
    event = data.get("event") if isinstance(data, dict) and "event" in data else data
    return validate_event_obj(event, mode=mode, keys=keys, expected_audience=expected_audience)


def validate_chain_file(path, mode="archival", keys=None):
    events = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line, object_pairs_hook=no_duplicates_object_pairs_hook))
    known = {}
    results = []
    for event in events:
        res = validate_event_obj(event, mode=mode, keys=keys, known_hashes=known)
        results.append(res)
        if res["event_hash"]:
            known[res["event_hash"]] = event
    valid = all(r["valid"] for r in results)
    return {
        "valid": valid,
        "mode": mode,
        "profile": "jep-core-0.6",
        "event_count": len(events),
        "results": results,
    }


def run_tests(root, keys):
    root = Path(root)
    cases = []
    for path in sorted((root / "valid").glob("*.json")):
        if path.name == "public-keys.json":
            continue
        cases.append((path, True))
    for path in sorted((root / "invalid").glob("*.json")):
        cases.append((path, False))

    passed = 0
    failed = 0
    details = []
    for path, expected_valid in cases:
        res = validate_event_file(path, keys=keys)
        ok = (res["valid"] == expected_valid)
        if ok:
            passed += 1
        else:
            failed += 1
        details.append({
            "path": str(path),
            "expected_valid": expected_valid,
            "actual_valid": res["valid"],
            "ok": ok,
            "errors": res.get("errors", []),
        })
    return {"passed": passed, "failed": failed, "details": details}


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate")
    v.add_argument("event")
    v.add_argument("--keys")
    v.add_argument("--mode", default="archival")
    v.add_argument("--aud")

    c = sub.add_parser("validate-chain")
    c.add_argument("chain")
    c.add_argument("--keys")
    c.add_argument("--mode", default="archival")

    t = sub.add_parser("run-tests")
    t.add_argument("test_vectors")
    t.add_argument("--keys")

    args = ap.parse_args()
    keys = load_keys(getattr(args, "keys", None))

    if args.cmd == "validate":
        out = validate_event_file(args.event, mode=args.mode, keys=keys, expected_audience=args.aud)
    elif args.cmd == "validate-chain":
        out = validate_chain_file(args.chain, mode=args.mode, keys=keys)
    elif args.cmd == "run-tests":
        out = run_tests(args.test_vectors, keys)
    else:
        raise SystemExit(2)

    print(json.dumps(out, indent=2))
    if isinstance(out, dict) and out.get("failed", 0):
        raise SystemExit(1)
    if isinstance(out, dict) and out.get("valid") is False:
        # Validation failure is expected for invalid inputs; command exits 1 only for direct validate.
        raise SystemExit(1)


if __name__ == "__main__":
    main()

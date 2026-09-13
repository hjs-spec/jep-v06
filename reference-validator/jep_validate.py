#!/usr/bin/env python3
"""JEP v0.6 reference validator.

This implementation targets the JEP-Core-0.6 validation order and the
JEP-Baseline-Ed25519-JWS-JCS-0.6 conformance class. It deliberately keeps
legal, policy, factual, and external authorization determinations outside
JEP-Core.

Implemented validation stages:
  Level 0: JSON/I-JSON, duplicate-member rejection, core and verb shape.
  Level 1: RFC 8785 JCS, event hash, detached compact JWS/Ed25519.
  Level 2: optional local test trust profiles for actor/key binding.
  Level 3: basic reference-chain validation, replay checks, cycle detection,
           termination reuse checks, and observed-log reporting.

This remains a reference/conformance implementation, not a production key,
policy, evidence, or legal-liability engine.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import sys
import tempfile
from nacl.signing import VerifyKey
from contextlib import contextmanager
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping, Sequence

import rfc8785

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:  # pragma: no cover - reported as a validation failure
    Ed25519PublicKey = None

CORE_PROFILE = "jep-core-0.6"
BASELINE_CLASS = "JEP-Baseline-Ed25519-JWS-JCS-0.6"
CHAIN_CLASS = "JEP-Chain-0.6 Verifier"
WIRE_VERSION = "1"
VERBS = {"J", "D", "T", "V"}
EVENT_MODES = {"acceptance", "archival"}
TOP_LEVEL_FIELDS = {
    "jep", "verb", "who", "when", "what", "nonce", "aud", "ref",
    "ext", "ext_crit", "sig",
}
DIGEST_RE = re.compile(r"^[a-z0-9][a-z0-9-]*:[0-9a-f]+$")
B64U_RE = re.compile(r"^[A-Za-z0-9_-]*$")
SAFE_INTEGER_MAX = 2**53 - 1

# No JEP critical extensions are treated as implemented merely because their
# identifiers are known. Handlers must be added here before a critical
# extension can be accepted.
CRITICAL_EXTENSION_HANDLERS: dict[str, Any] = {}


class DuplicateKeyError(ValueError):
    pass


@dataclass
class ValidationFault(Exception):
    code: str
    message: str
    failed_level: int
    recoverable: bool = False
    evidence: list[str] | None = None

    def as_error(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "level": self.failed_level,
            "recoverable": self.recoverable,
        }
        if self.evidence:
            out["evidence"] = self.evidence
        return out


def _no_duplicates_object_pairs_hook(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicateKeyError(f"duplicate JSON member: {key}")
        obj[key] = value
    return obj


def _reject_non_json_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant: {value}")


def parse_json_text(text: str) -> Any:
    value = json.loads(
        text,
        object_pairs_hook=_no_duplicates_object_pairs_hook,
        parse_constant=_reject_non_json_constant,
    )
    _validate_i_json(value)
    return value


def load_json_no_duplicates(path: str | Path) -> Any:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValidationFault("ERR_INVALID_JSON", f"JSON is not valid UTF-8: {exc}", 0) from exc
    try:
        return parse_json_text(text)
    except DuplicateKeyError as exc:
        raise ValidationFault("ERR_DUPLICATE_MEMBER", str(exc), 0) from exc
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValidationFault("ERR_INVALID_JSON", f"invalid JSON: {exc}", 0) from exc


def _validate_i_json(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > SAFE_INTEGER_MAX:
            raise ValueError(f"{path}: integer exceeds the interoperable IEEE-754 safe range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path}: non-finite number is not I-JSON")
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError(f"{path}: string contains an unpaired surrogate") from exc
        return
    if isinstance(value, list):
        for idx, item in enumerate(value):
            _validate_i_json(item, f"{path}[{idx}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path}: object member names must be strings")
            _validate_i_json(key, f"{path}.<key>")
            _validate_i_json(item, f"{path}.{key}")
        return
    raise ValueError(f"{path}: unsupported JSON value type {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except Exception as exc:
        raise ValidationFault("ERR_CANONICALIZATION_FAILED", f"RFC 8785 canonicalization failed: {exc}", 1) from exc


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(value: str, *, label: str) -> bytes:
    if not isinstance(value, str) or not B64U_RE.fullmatch(value):
        raise ValidationFault("ERR_SIGNATURE_CONTAINER_INVALID", f"{label} is not unpadded base64url", 1)
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if b64u(raw) != value:
            raise ValueError("non-canonical base64url")
        return raw
    except Exception as exc:
        raise ValidationFault("ERR_SIGNATURE_CONTAINER_INVALID", f"invalid {label}: {exc}", 1) from exc


def event_hash(event: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonicalize(dict(event))).hexdigest()


def _error_result(
    fault: ValidationFault,
    *,
    highest_completed: int,
    mode: str,
    profile: str,
    conformance_class: str,
    event_hash_value: str | None = None,
    scopes: Sequence[str] = (),
    warnings: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    return {
        "valid": False,
        "level": max(0, highest_completed),
        "mode": mode,
        "profile": profile,
        "conformance_class": conformance_class,
        "scopes": list(scopes),
        "event_hash": event_hash_value,
        "warnings": list(warnings),
        "errors": [fault.as_error()],
    }


def _success_result(
    *,
    level: int,
    mode: str,
    profile: str,
    conformance_class: str,
    event_hash_value: str | None,
    scopes: Sequence[str],
    warnings: Sequence[Mapping[str, Any]] = (),
    **extra: Any,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "valid": True,
        "level": level,
        "mode": mode,
        "profile": profile,
        "conformance_class": conformance_class,
        "scopes": list(scopes),
        "event_hash": event_hash_value,
        "warnings": list(warnings),
        "errors": [],
    }
    out.update(extra)
    return out


def _require(condition: bool, code: str, message: str, level: int = 0) -> None:
    if not condition:
        raise ValidationFault(code, message, level)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_digest(value: str, *, field: str) -> None:
    _require(isinstance(value, str) and bool(DIGEST_RE.fullmatch(value)),
             "ERR_INVALID_FIELD_TYPE", f"{field} must be an algorithm-tagged lowercase hexadecimal digest", 0)
    algorithm, digest = value.split(":", 1)
    if algorithm == "sha256":
        _require(len(digest) == 64, "ERR_INVALID_FIELD_TYPE", f"{field} sha256 digest must contain 64 hex characters", 0)


def _validate_what(value: Any, *, field: str = "what") -> None:
    if isinstance(value, str):
        _validate_digest(value, field=field)
        return
    _require(isinstance(value, dict), "ERR_INVALID_FIELD_TYPE", f"{field} must be an object or algorithm-tagged digest", 0)
    _require(bool(value), "ERR_INVALID_FIELD_TYPE", f"{field} object must not be empty", 0)
    if "claim" in value:
        _require(isinstance(value["claim"], str) and bool(value["claim"]),
                 "ERR_INVALID_FIELD_TYPE", f"{field}.claim must be a non-empty string", 0)


def _validate_ref(value: Any, *, field: str = "ref", allow_null: bool = True) -> None:
    if value is None:
        _require(allow_null, "ERR_MISSING_REQUIRED_FIELD", f"{field} must not be null", 0)
        return
    if isinstance(value, str):
        _validate_digest(value, field=field)
        return
    _require(isinstance(value, dict), "ERR_INVALID_FIELD_TYPE", f"{field} must be null, a digest string, or a typed reference object", 0)
    _require("type" in value and "value" in value, "ERR_MISSING_REQUIRED_FIELD", f"{field} object requires type and value", 0)
    _require(isinstance(value["type"], str) and bool(value["type"]),
             "ERR_INVALID_FIELD_TYPE", f"{field}.type must be a non-empty string", 0)
    if "hash" in value:
        _validate_digest(value["hash"], field=f"{field}.hash")


def validate_event_shape(event: Any) -> dict[str, Any]:
    _require(isinstance(event, dict), "ERR_INVALID_FIELD_TYPE", "a JEP event must be a JSON object", 0)
    unknown = sorted(set(event) - TOP_LEVEL_FIELDS)
    _require(not unknown, "ERR_INVALID_FIELD_TYPE", f"unknown top-level member(s): {', '.join(unknown)}; use ext for extensions", 0)

    for field in ("jep", "verb", "who", "when", "nonce"):
        _require(field in event, "ERR_MISSING_REQUIRED_FIELD", f"missing required field: {field}", 0)
    if "sig" not in event:
        raise ValidationFault("ERR_SIGNATURE_MISSING", "missing required field: sig", 1)

    _require(isinstance(event["jep"], str), "ERR_INVALID_FIELD_TYPE", "jep must be a string", 0)
    _require(event["jep"] == WIRE_VERSION, "ERR_UNSUPPORTED_JEP_VERSION", f"jep must be {WIRE_VERSION!r}", 0)
    _require(isinstance(event["verb"], str), "ERR_INVALID_FIELD_TYPE", "verb must be a string", 0)
    _require(event["verb"] in VERBS, "ERR_UNKNOWN_VERB", "verb must be one of J, D, T, or V", 0)
    _require(isinstance(event["who"], str) and bool(event["who"]),
             "ERR_INVALID_FIELD_TYPE", "who must be a non-empty actor identifier string", 0)
    _require(_is_int(event["when"]), "ERR_INVALID_TIMESTAMP", "when must be an integer Unix timestamp", 0)
    _require(isinstance(event["nonce"], str), "ERR_INVALID_FIELD_TYPE", "nonce must be a UUIDv4 string", 0)
    try:
        parsed_nonce = uuid.UUID(event["nonce"])
    except (ValueError, AttributeError) as exc:
        raise ValidationFault("ERR_INVALID_FIELD_TYPE", "nonce must be a canonical UUIDv4 string", 0) from exc
    _require(parsed_nonce.version == 4 and str(parsed_nonce) == event["nonce"].lower(),
             "ERR_INVALID_FIELD_TYPE", "nonce must be a canonical UUIDv4 string", 0)

    if "aud" in event:
        _require(isinstance(event["aud"], str) and bool(event["aud"]),
                 "ERR_INVALID_FIELD_TYPE", "aud must be a non-empty string", 0)
    if "ref" in event:
        _validate_ref(event["ref"])
    if "ext" in event:
        _require(isinstance(event["ext"], dict), "ERR_INVALID_FIELD_TYPE", "ext must be an object", 0)
        for ext_id, ext_value in event["ext"].items():
            _require(isinstance(ext_id, str) and bool(ext_id), "ERR_INVALID_FIELD_TYPE", "extension identifiers must be non-empty strings", 0)
            _require(isinstance(ext_value, dict), "ERR_INVALID_FIELD_TYPE", f"extension {ext_id!r} must contain an object", 0)
    if "ext_crit" in event:
        crit = event["ext_crit"]
        _require(isinstance(crit, list), "ERR_INVALID_FIELD_TYPE", "ext_crit must be an array", 0)
        _require(all(isinstance(x, str) and bool(x) for x in crit), "ERR_INVALID_FIELD_TYPE", "ext_crit entries must be non-empty strings", 0)
        _require(len(crit) == len(set(crit)), "ERR_INVALID_FIELD_TYPE", "ext_crit entries must be unique", 0)
    _require(isinstance(event["sig"], str) and bool(event["sig"]),
             "ERR_SIGNATURE_CONTAINER_INVALID", "the baseline sig member must be a non-empty detached compact JWS string", 1)

    verb = event["verb"]
    _require("what" in event and event["what"] is not None,
             "ERR_MISSING_REQUIRED_FIELD", f"{verb} events require a non-null what member", 0)
    _validate_what(event["what"])

    if verb == "D":
        _require("ref" in event, "ERR_MISSING_REQUIRED_FIELD", "D events require ref in the v0.6 baseline shape", 0)
        if isinstance(event["what"], dict):
            for field in ("claim", "delegatee", "scope"):
                _require(field in event["what"], "ERR_MISSING_REQUIRED_FIELD", f"D event object requires what.{field}", 0)
            _require(isinstance(event["what"]["delegatee"], str) and bool(event["what"]["delegatee"]),
                     "ERR_INVALID_FIELD_TYPE", "what.delegatee must be a non-empty string", 0)
            _require(event["what"]["scope"] is not None, "ERR_INVALID_FIELD_TYPE", "what.scope must not be null", 0)
    elif verb == "T":
        _require("ref" in event, "ERR_MISSING_REQUIRED_FIELD", "T events require ref in the v0.6 baseline shape", 0)
        if isinstance(event["what"], dict):
            for field in ("claim", "target", "termination_scope"):
                _require(field in event["what"], "ERR_MISSING_REQUIRED_FIELD", f"T event object requires what.{field}", 0)
            _require(event["what"]["target"] is not None, "ERR_INVALID_FIELD_TYPE", "what.target must not be null", 0)
            _require(isinstance(event["what"]["termination_scope"], str) and bool(event["what"]["termination_scope"]),
                     "ERR_INVALID_FIELD_TYPE", "what.termination_scope must be a non-empty string", 0)
    elif verb == "V":
        _require("ref" in event and event["ref"] is not None,
                 "ERR_MISSING_REQUIRED_FIELD", "V events require a non-null ref", 0)
        if isinstance(event["what"], dict):
            _require("verification_scope" in event["what"],
                     "ERR_MISSING_REQUIRED_FIELD", "V event object requires what.verification_scope", 0)
            scopes = event["what"]["verification_scope"]
            _require(isinstance(scopes, list) and bool(scopes),
                     "ERR_INVALID_FIELD_TYPE", "what.verification_scope must be a non-empty array", 0)
            _require(all(isinstance(x, str) and bool(x) for x in scopes),
                     "ERR_INVALID_FIELD_TYPE", "verification scopes must be non-empty strings", 0)
            _require(len(scopes) == len(set(scopes)),
                     "ERR_INVALID_FIELD_TYPE", "verification scopes must be unique", 0)

    return event


def load_keys(path: str | Path | None) -> dict[str, dict[str, Any]]:
    if not path:
        return {}
    data = load_json_no_duplicates(path)
    if not isinstance(data, dict):
        raise ValidationFault("ERR_INVALID_FIELD_TYPE", "key file must contain a JSON object", 0)
    out: dict[str, dict[str, Any]] = {}
    for logical_name, value in data.items():
        if not isinstance(value, dict):
            continue
        kid = value.get("kid")
        if isinstance(kid, str) and kid:
            out[kid] = value
        elif isinstance(logical_name, str) and isinstance(value.get("x"), str):
            out[logical_name] = value
    return out


def _parse_protected_header(protected_b64: str) -> dict[str, Any]:
    raw = b64u_decode(protected_b64, label="JWS protected header")
    try:
        header = parse_json_text(raw.decode("utf-8", errors="strict"))
    except DuplicateKeyError as exc:
        raise ValidationFault("ERR_SIGNATURE_CONTAINER_INVALID", f"duplicate protected-header member: {exc}", 1) from exc
    except Exception as exc:
        raise ValidationFault("ERR_SIGNATURE_CONTAINER_INVALID", f"invalid JWS protected header: {exc}", 1) from exc
    _require(isinstance(header, dict), "ERR_SIGNATURE_CONTAINER_INVALID", "JWS protected header must be an object", 1)

    crit = header.get("crit")
    if crit is not None:
        _require(isinstance(crit, list) and bool(crit), "ERR_SIGNATURE_CONTAINER_INVALID", "JWS crit must be a non-empty array", 1)
        _require(all(isinstance(x, str) and bool(x) for x in crit), "ERR_SIGNATURE_CONTAINER_INVALID", "JWS crit entries must be non-empty strings", 1)
        _require(len(crit) == len(set(crit)), "ERR_SIGNATURE_CONTAINER_INVALID", "JWS crit entries must be unique", 1)
        for name in crit:
            _require(name in header, "ERR_SIGNATURE_CONTAINER_INVALID", f"critical JOSE parameter {name!r} is absent", 1)
        # The baseline defines no private JOSE critical-header handlers.
        raise ValidationFault("ERR_SIGNATURE_CONTAINER_INVALID", f"unsupported critical JOSE parameter(s): {', '.join(crit)}", 1)

    if "b64" in header and header["b64"] is not True:
        raise ValidationFault("ERR_SIGNATURE_CONTAINER_INVALID", "the baseline requires ordinary base64url JWS payload encoding", 1)
    return header


def verify_detached_jws(event: Mapping[str, Any], payload: bytes, keys: Mapping[str, Mapping[str, Any]]) -> tuple[str, Mapping[str, Any]]:
    sig = event.get("sig")
    if not isinstance(sig, str):
        raise ValidationFault("ERR_SIGNATURE_CONTAINER_INVALID", "sig is not a detached compact JWS string", 1)
    parts = sig.split(".")
    _require(len(parts) == 3 and parts[1] == "", "ERR_SIGNATURE_CONTAINER_INVALID", "detached compact JWS must contain an empty payload segment", 1)
    protected_b64, _, signature_b64 = parts
    header = _parse_protected_header(protected_b64)

    alg = header.get("alg")
    _require(isinstance(alg, str), "ERR_SIGNATURE_CONTAINER_INVALID", "JWS protected header requires alg", 1)
    if alg != "Ed25519":
        raise ValidationFault("ERR_UNSUPPORTED_SIGNATURE_ALG", f"unsupported baseline alg: {alg}", 1)
    kid = header.get("kid")
    _require(isinstance(kid, str) and bool(kid), "ERR_SIGNATURE_CONTAINER_INVALID", "JWS protected header requires a non-empty kid", 1)

    jwk = keys.get(kid)
    if jwk is None:
        raise ValidationFault("ERR_KEY_UNRESOLVED", f"no public key found for kid: {kid}", 1)
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValidationFault("ERR_ALG_KEY_TYPE_MISMATCH", "Ed25519 requires an OKP/Ed25519 JWK", 1)
    if jwk.get("alg") not in (None, "Ed25519"):
        raise ValidationFault("ERR_ALG_PROFILE_MISMATCH", "JWK alg is inconsistent with the JWS alg", 1)
    if jwk.get("use") not in (None, "sig"):
        raise ValidationFault("ERR_PROHIBITED_SIGNATURE_ALG", "JWK use does not permit signatures", 1)
    key_ops = jwk.get("key_ops")
    if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
        raise ValidationFault("ERR_PROHIBITED_SIGNATURE_ALG", "JWK key_ops does not permit verification", 1)

    x = jwk.get("x")
    _require(isinstance(x, str), "ERR_ALG_KEY_TYPE_MISMATCH", "Ed25519 JWK requires x", 1)
    raw_key = b64u_decode(x, label="JWK x")
    raw_signature = b64u_decode(signature_b64, label="JWS signature")
    _require(len(raw_key) == 32, "ERR_ALG_KEY_TYPE_MISMATCH", "Ed25519 public key must be 32 bytes", 1)
    _require(len(raw_signature) == 64, "ERR_SIGNATURE_INVALID", "Ed25519 signature must be 64 bytes", 1)
    if Ed25519PublicKey is None:
        raise ValidationFault("ERR_SIGNATURE_INVALID", "cryptography package is unavailable", 1)
    signing_input = (protected_b64 + "." + b64u(payload)).encode("ascii")
    try:
        VerifyKey(raw_key).verify(signing_input, raw_signature)
    except Exception as exc:
        raise ValidationFault("ERR_SIGNATURE_INVALID", "Ed25519 signature verification failed", 1) from exc
    return kid, jwk


def check_actor_binding(event: Mapping[str, Any], kid: str, jwk: Mapping[str, Any], trust_profile: str) -> None:
    if trust_profile == "none":
        return
    if jwk.get("revoked") is True:
        raise ValidationFault("ERR_KEY_REVOKED", f"key is revoked under trust profile: {kid}", 2)
    actor = event["who"]
    if trust_profile == "kid-prefix":
        controller = kid.split("#", 1)[0]
        if controller != actor:
            raise ValidationFault("ERR_KEY_NOT_BOUND_TO_ACTOR", f"kid controller {controller!r} is not actor {actor!r}", 2)
        return
    if trust_profile == "inline":
        actors: list[str] = []
        if isinstance(jwk.get("actor"), str):
            actors.append(jwk["actor"])
        if isinstance(jwk.get("actors"), list):
            actors.extend(x for x in jwk["actors"] if isinstance(x, str))
        if actor not in actors:
            raise ValidationFault("ERR_KEY_NOT_BOUND_TO_ACTOR", f"key {kid!r} is not bound to actor {actor!r}", 2)
        return
    raise ValidationFault("ERR_TRUST_PROFILE_UNSUPPORTED", f"unsupported local trust profile: {trust_profile}", 2)


def _process_critical_extensions(event: Mapping[str, Any]) -> None:
    critical = event.get("ext_crit") or []
    extensions = event.get("ext") or {}
    for ext_id in critical:
        if ext_id not in extensions:
            raise ValidationFault("ERR_EXTENSION_SCHEMA_INVALID", f"critical extension {ext_id!r} is absent from ext", 3)
        handler = CRITICAL_EXTENSION_HANDLERS.get(ext_id)
        if handler is None:
            raise ValidationFault("ERR_UNKNOWN_CRITICAL_EXTENSION", f"unsupported critical extension: {ext_id}", 3)
        try:
            handler(extensions[ext_id], event)
        except ValidationFault:
            raise
        except Exception as exc:
            raise ValidationFault("ERR_EXTENSION_VALIDATION_FAILED", f"critical extension {ext_id!r} failed: {exc}", 3) from exc


def _reference_digest(ref: Any) -> str | None:
    if isinstance(ref, str) and DIGEST_RE.fullmatch(ref):
        return ref
    if isinstance(ref, dict):
        if isinstance(ref.get("hash"), str) and DIGEST_RE.fullmatch(ref["hash"]):
            return ref["hash"]
        value = ref.get("value")
        if isinstance(value, str) and DIGEST_RE.fullmatch(value):
            return value
    return None


def _nonce_context(event: Mapping[str, Any], profile: str) -> str:
    fields = (event.get("who", ""), event.get("aud", ""), profile, event.get("nonce", ""))
    return "v2:" + "".join(f"{len(value.encode('utf-8'))}:{value}" for value in fields)


def _legacy_nonce_context(event: Mapping[str, Any], profile: str) -> str:
    return "\x1f".join((str(event.get("who", "")), str(event.get("aud", "")), profile, str(event.get("nonce", ""))))


def _load_replay_cache(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        data = load_json_no_duplicates(path)
    except ValidationFault as exc:
        raise ValidationFault("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", f"invalid replay cache: {exc.message}", 3) from exc
    if isinstance(data, list) and all(isinstance(x, str) for x in data):
        return set(data)
    raise ValidationFault("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "replay cache must be a JSON array of strings", 3)


@contextmanager
def _replay_lock(path: Path):
    lock = path.with_name(path.name + ".consume-lock")
    lock.mkdir(mode=0o700)
    try:
        yield
    finally:
        lock.rmdir()


def _save_replay_cache(path: Path, values: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(sorted(set(values)), indent=2) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def validate_event_obj(
    event: Any,
    *,
    mode: str = "archival",
    keys: Mapping[str, Mapping[str, Any]] | None = None,
    trust_profile: str = "none",
    expected_audience: str | None = None,
    now: int | None = None,
    max_age: int = 300,
    max_future_skew: int = 60,
    replay_cache_path: str | Path | None = None,
    known_hashes: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    keys = keys or {}
    profile = CORE_PROFILE if trust_profile == "none" else f"{CORE_PROFILE}+local-{trust_profile}"
    highest = -1
    scopes: list[str] = []
    ehash: str | None = None
    try:
        _require(mode in EVENT_MODES, "ERR_DOMAIN_REQUIREMENT_UNSATISFIED", f"unsupported event validation mode: {mode}", 4)
        validate_event_shape(event)
        highest = 0
        scopes.append("syntax")

        unsigned = {key: value for key, value in event.items() if key != "sig"}
        payload = canonicalize(unsigned)
        ehash = event_hash(event)
        kid, jwk = verify_detached_jws(event, payload, keys)
        highest = 1
        scopes.append("cryptographic")

        check_actor_binding(event, kid, jwk, trust_profile)
        if trust_profile != "none":
            highest = 2
            scopes.append("actor_binding")

        replay_cache: set[str] | None = None
        replay_key: str | None = None
        if mode == "acceptance":
            _require(_is_int(max_age) and max_age >= 0, "ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "max_age must be a non-negative integer", 4)
            _require(_is_int(max_future_skew) and max_future_skew >= 0, "ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "max_future_skew must be a non-negative integer", 4)
            current = int(time.time()) if now is None else now
            _require(_is_int(current), "ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "now must be an integer Unix timestamp", 4)
            if event["when"] < current - max_age:
                raise ValidationFault("ERR_EVENT_EXPIRED", "event is older than the acceptance freshness window", 3)
            if event["when"] > current + max_future_skew:
                raise ValidationFault("ERR_TIMESTAMP_OUT_OF_WINDOW", "event timestamp is too far in the future", 3)
            _require(replay_cache_path is not None, "ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "acceptance mode requires a persistent replay cache", 3)
            replay_cache = _load_replay_cache(Path(replay_cache_path))
            replay_key = _nonce_context(event, profile)
            if replay_key in replay_cache or _legacy_nonce_context(event, profile) in replay_cache:
                raise ValidationFault("ERR_NONCE_REPLAY", "nonce has already been accepted in this actor/audience/profile context", 3)

        if expected_audience is not None and event.get("aud") != expected_audience:
            raise ValidationFault("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "aud does not match the expected validation context", 4)

        if known_hashes is not None:
            digest = _reference_digest(event.get("ref"))
            if digest is not None and digest not in known_hashes:
                raise ValidationFault("ERR_REF_UNRESOLVED", f"referenced event not found: {digest}", 3)

        _process_critical_extensions(event)

        if mode == "acceptance" and replay_cache is not None and replay_key is not None:
            cache_path = Path(replay_cache_path).resolve()
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            with _replay_lock(cache_path):
                # Re-read while locked: atomic rename alone does not make consumption atomic.
                replay_cache = _load_replay_cache(cache_path)
                if replay_key in replay_cache or _legacy_nonce_context(event, profile) in replay_cache:
                    raise ValidationFault("ERR_NONCE_REPLAY", "nonce has already been accepted in this context", 3)
                replay_cache.add(replay_key)
                _save_replay_cache(cache_path, replay_cache)

        return _success_result(
            level=highest,
            mode=mode,
            profile=profile,
            conformance_class=BASELINE_CLASS,
            event_hash_value=ehash,
            scopes=scopes,
        )
    except (OSError, TimeoutError) as exc:
        return _error_result(ValidationFault("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", f"replay cache unavailable: {exc}", 3), highest_completed=highest, mode=mode, profile=profile, conformance_class=BASELINE_CLASS, event_hash_value=ehash, scopes=scopes)
    except ValidationFault as fault:
        return _error_result(
            fault,
            highest_completed=highest,
            mode=mode,
            profile=profile,
            conformance_class=BASELINE_CLASS,
            event_hash_value=ehash,
            scopes=scopes,
        )


def validate_event_file(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    mode = kwargs.get("mode", "archival")
    trust_profile = kwargs.get("trust_profile", "none")
    profile = CORE_PROFILE if trust_profile == "none" else f"{CORE_PROFILE}+local-{trust_profile}"
    try:
        data = load_json_no_duplicates(path)
    except ValidationFault as fault:
        return _error_result(
            fault,
            highest_completed=-1,
            mode=mode,
            profile=profile,
            conformance_class=BASELINE_CLASS,
        )
    event = data.get("event") if isinstance(data, dict) and "event" in data else data
    return validate_event_obj(event, **kwargs)


def _detect_reference_cycle(adjacency: Mapping[str, set[str]]) -> list[str] | None:
    visiting: set[str] = set()
    visited: set[str] = set()
    path: list[str] = []

    def visit(node: str) -> list[str] | None:
        if node in visiting:
            idx = path.index(node)
            return path[idx:] + [node]
        if node in visited:
            return None
        visiting.add(node)
        path.append(node)
        for nxt in adjacency.get(node, set()):
            cycle = visit(nxt)
            if cycle:
                return cycle
        path.pop()
        visiting.remove(node)
        visited.add(node)
        return None

    for node in adjacency:
        cycle = visit(node)
        if cycle:
            return cycle
    return None


def validate_chain_file(
    path: str | Path,
    *,
    keys: Mapping[str, Mapping[str, Any]] | None = None,
    trust_profile: str = "none",
    log_assumption: str = "partial",
) -> dict[str, Any]:
    keys = keys or {}
    profile = CORE_PROFILE if trust_profile == "none" else f"{CORE_PROFILE}+local-{trust_profile}"
    events: list[dict[str, Any]] = []
    try:
        _require(log_assumption in {"partial", "complete"}, "ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "log_assumption must be partial or complete", 4)
        for line_number, line in enumerate(Path(path).read_text(encoding="utf-8", errors="strict").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                event = parse_json_text(line)
            except DuplicateKeyError as exc:
                raise ValidationFault("ERR_DUPLICATE_MEMBER", f"line {line_number}: {exc}", 0) from exc
            except Exception as exc:
                raise ValidationFault("ERR_INVALID_JSON", f"line {line_number}: {exc}", 0) from exc
            _require(isinstance(event, dict), "ERR_INVALID_FIELD_TYPE", f"line {line_number}: chain member must be an event object", 0)
            events.append(event)
    except (OSError, UnicodeError) as exc:
        fault = ValidationFault("ERR_INVALID_JSON", f"cannot read chain: {exc}", 0)
        return _error_result(fault, highest_completed=-1, mode="chain", profile=profile, conformance_class=CHAIN_CLASS)
    except ValidationFault as fault:
        return _error_result(fault, highest_completed=-1, mode="chain", profile=profile, conformance_class=CHAIN_CLASS)

    if not events:
        fault = ValidationFault("ERR_MISSING_REQUIRED_FIELD", "chain contains no events", 0)
        return _error_result(fault, highest_completed=-1, mode="chain", profile=profile, conformance_class=CHAIN_CLASS)

    results: list[dict[str, Any]] = []
    hashes: dict[str, dict[str, Any]] = {}
    minimum_level = 4
    for event in events:
        result = validate_event_obj(event, mode="archival", keys=keys, trust_profile=trust_profile)
        results.append(result)
        minimum_level = min(minimum_level, result["level"])
        if not result["valid"]:
            return {
                "valid": False,
                "level": minimum_level,
                "mode": "chain",
                "profile": profile,
                "conformance_class": CHAIN_CLASS,
                "scopes": ["syntax"] if minimum_level == 0 else ["syntax", "cryptographic"],
                "event_hash": None,
                "warnings": [],
                "errors": result["errors"],
                "event_count": len(events),
                "results": results,
                "log_assumption": log_assumption,
            }
        hashes[result["event_hash"]] = event

    try:
        adjacency: dict[str, set[str]] = {digest: set() for digest in hashes}
        seen_nonce_contexts: set[str] = set()
        terminated: set[str] = set()
        for result, event in zip(results, events):
            digest = result["event_hash"]
            nonce_key = _nonce_context(event, profile)
            if nonce_key in seen_nonce_contexts:
                raise ValidationFault("ERR_NONCE_REPLAY", "duplicate nonce context in observed chain", 3, evidence=[digest])
            seen_nonce_contexts.add(nonce_key)

            target = _reference_digest(event.get("ref"))
            if target is not None:
                if target not in hashes:
                    raise ValidationFault("ERR_REF_UNRESOLVED", f"unresolved chain reference: {target}", 3, evidence=[digest, target])
                adjacency[digest].add(target)
                if event.get("verb") in {"J", "D"} and target in terminated:
                    raise ValidationFault("ERR_TERMINATED_REFERENCE_REUSED", f"event relies on a terminated reference: {target}", 3, evidence=[digest, target])

            if event.get("verb") == "T":
                what = event.get("what")
                termination_target = _reference_digest(what.get("target")) if isinstance(what, dict) else None
                termination_target = termination_target or target
                if termination_target is None:
                    raise ValidationFault("ERR_MISSING_REQUIRED_FIELD", "T event does not identify a digest-addressed target for chain processing", 3, evidence=[digest])
                if termination_target not in hashes:
                    raise ValidationFault("ERR_REF_UNRESOLVED", f"termination target not found: {termination_target}", 3, evidence=[digest, termination_target])
                terminated.add(termination_target)

        cycle = _detect_reference_cycle(adjacency)
        if cycle:
            raise ValidationFault("ERR_CYCLE_DETECTED", "reference cycle detected", 3, evidence=cycle)

        _process_chain_extensions(events)
        chain_level = 3 if minimum_level >= 2 else minimum_level
        scopes = ["syntax", "cryptographic"]
        if minimum_level >= 2:
            scopes.append("actor_binding")
        scopes.extend(["chain_integrity", "extension_processing"])
        return _success_result(
            level=chain_level,
            mode="chain",
            profile=profile,
            conformance_class=CHAIN_CLASS,
            event_hash_value=None,
            scopes=scopes,
            event_count=len(events),
            results=results,
            log_assumption=log_assumption,
            terminated_references=sorted(terminated),
        )
    except ValidationFault as fault:
        return {
            "valid": False,
            "level": min(minimum_level, 2) if minimum_level != 4 else 0,
            "mode": "chain",
            "profile": profile,
            "conformance_class": CHAIN_CLASS,
            "scopes": ["syntax", "cryptographic"] + (["actor_binding"] if minimum_level >= 2 else []),
            "event_hash": None,
            "warnings": [],
            "errors": [fault.as_error()],
            "event_count": len(events),
            "results": results,
            "log_assumption": log_assumption,
        }


def _process_chain_extensions(events: Sequence[Mapping[str, Any]]) -> None:
    for event in events:
        _process_critical_extensions(event)


def _resolve_case_path(manifest_path: Path, value: str | None) -> Path | None:
    if value is None:
        return None
    return (manifest_path.parent / value).resolve()


def run_tests(manifest_or_root: str | Path) -> dict[str, Any]:
    path = Path(manifest_or_root)
    manifest_path = path / "test-manifest.json" if path.is_dir() else path
    manifest = load_json_no_duplicates(manifest_path)
    _require(isinstance(manifest, dict) and isinstance(manifest.get("cases"), list),
             "ERR_INVALID_FIELD_TYPE", "test manifest requires a cases array", 0)

    details: list[dict[str, Any]] = []
    passed = 0
    failed = 0
    for case in manifest["cases"]:
        name = str(case.get("name", "unnamed"))
        kind = case.get("kind", "event")
        case_path = _resolve_case_path(manifest_path, case.get("path"))
        _require(case_path is not None, "ERR_MISSING_REQUIRED_FIELD", f"test case {name!r} requires path", 0)
        keys_path = _resolve_case_path(manifest_path, case.get("keys"))
        keys = load_keys(keys_path) if keys_path else {}
        trust_profile = case.get("trust_profile", "none")
        if kind == "event":
            result = validate_event_file(
                case_path,
                mode=case.get("mode", "archival"),
                keys=keys,
                trust_profile=trust_profile,
                expected_audience=case.get("expected_audience"),
                now=case.get("now"),
                max_age=case.get("max_age", 300),
                max_future_skew=case.get("max_future_skew", 60),
                replay_cache_path=_resolve_case_path(manifest_path, case.get("replay_cache")),
            )
        elif kind == "chain":
            result = validate_chain_file(
                case_path,
                keys=keys,
                trust_profile=trust_profile,
                log_assumption=case.get("log_assumption", "partial"),
            )
        elif kind == "canonicalization":
            source = load_json_no_duplicates(case_path)
            actual = canonicalize(source).decode("utf-8")
            expected_path = _resolve_case_path(manifest_path, case.get("expected_path"))
            expected = expected_path.read_text(encoding="utf-8").strip()
            result = {
                "valid": actual == expected,
                "level": 1 if actual == expected else 0,
                "errors": [] if actual == expected else [{"code": "ERR_CANONICALIZATION_FAILED", "message": "canonical output mismatch"}],
                "actual": actual,
                "expected": expected,
            }
        else:
            result = {"valid": False, "level": 0, "errors": [{"code": "ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "message": f"unknown test kind: {kind}"}]}

        checks: list[str] = []
        expected_valid = case.get("expected_valid")
        if isinstance(expected_valid, bool) and result.get("valid") != expected_valid:
            checks.append(f"valid expected {expected_valid}, got {result.get('valid')}")
        expected_error = case.get("expected_error")
        actual_codes = [error.get("code") for error in result.get("errors", [])]
        if expected_error is not None and expected_error not in actual_codes:
            checks.append(f"expected error {expected_error}, got {actual_codes}")
        if expected_error is None and case.get("expected_valid") is True and actual_codes:
            checks.append(f"unexpected errors: {actual_codes}")
        if "expected_level" in case and result.get("level") != case["expected_level"]:
            checks.append(f"level expected {case['expected_level']}, got {result.get('level')}")
        if "minimum_level" in case and int(result.get("level", -1)) < int(case["minimum_level"]):
            checks.append(f"level expected >= {case['minimum_level']}, got {result.get('level')}")
        if "expected_event_hash" in case and result.get("event_hash") != case["expected_event_hash"]:
            checks.append("event hash mismatch")

        ok = not checks
        if ok:
            passed += 1
        else:
            failed += 1
        details.append({
            "name": name,
            "kind": kind,
            "path": str(case_path) if case_path else None,
            "ok": ok,
            "checks": checks,
            "actual_valid": result.get("valid"),
            "actual_level": result.get("level"),
            "actual_errors": actual_codes,
        })

    return {
        "suite": manifest.get("suite", "jep-v0.6-conformance"),
        "version": manifest.get("version", "0.6"),
        "passed": passed,
        "failed": failed,
        "details": details,
    }


def _load_keys_for_args(args: argparse.Namespace) -> dict[str, dict[str, Any]]:
    return load_keys(getattr(args, "keys", None))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="JEP v0.6 reference validator")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="validate one JEP event")
    validate.add_argument("event")
    validate.add_argument("--keys")
    validate.add_argument("--mode", choices=sorted(EVENT_MODES), default="archival")
    validate.add_argument("--trust-profile", choices=["none", "kid-prefix", "inline"], default="none")
    validate.add_argument("--aud")
    validate.add_argument("--now", type=int)
    validate.add_argument("--max-age", type=int, default=300)
    validate.add_argument("--max-future-skew", type=int, default=60)
    validate.add_argument("--replay-cache")

    chain = sub.add_parser("validate-chain", help="validate a JSONL event chain")
    chain.add_argument("chain")
    chain.add_argument("--keys")
    chain.add_argument("--trust-profile", choices=["none", "kid-prefix", "inline"], default="none")
    chain.add_argument("--log-assumption", choices=["partial", "complete"], default="partial")

    tests = sub.add_parser("run-tests", help="run the manifest-driven conformance suite")
    tests.add_argument("manifest_or_root", nargs="?", default=".")

    canon = sub.add_parser("canonicalize", help="emit RFC 8785 canonical JSON")
    canon.add_argument("json_file")

    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            output = validate_event_file(
                args.event,
                mode=args.mode,
                keys=_load_keys_for_args(args),
                trust_profile=args.trust_profile,
                expected_audience=args.aud,
                now=args.now,
                max_age=args.max_age,
                max_future_skew=args.max_future_skew,
                replay_cache_path=args.replay_cache,
            )
        elif args.command == "validate-chain":
            output = validate_chain_file(
                args.chain,
                keys=_load_keys_for_args(args),
                trust_profile=args.trust_profile,
                log_assumption=args.log_assumption,
            )
        elif args.command == "run-tests":
            output = run_tests(args.manifest_or_root)
        elif args.command == "canonicalize":
            value = load_json_no_duplicates(args.json_file)
            sys.stdout.buffer.write(canonicalize(value) + b"\n")
            return 0
        else:  # pragma: no cover
            parser.error("unknown command")
            return 2
    except ValidationFault as fault:
        output = _error_result(
            fault,
            highest_completed=-1,
            mode="archival",
            profile=CORE_PROFILE,
            conformance_class=BASELINE_CLASS,
        )

    print(json.dumps(output, ensure_ascii=False, indent=2))
    if args.command == "run-tests":
        return 1 if output.get("failed", 0) else 0
    return 0 if output.get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())

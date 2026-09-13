from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "reference-validator" / "jep_validate.py"
INTEROP = ROOT / "test-vectors" / "interop"
KEYS = INTEROP / "public-keys.json"
CHAIN_KEYS = ROOT / "test-vectors" / "valid" / "public-keys.json"
CHAIN = ROOT / "test-vectors" / "valid" / "delegation-verification-termination-chain.jsonl"


def run_validator(*args: str) -> tuple[subprocess.CompletedProcess[str], dict]:
    process = subprocess.run(
        [sys.executable, str(VALIDATOR), *map(str, args)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        output = json.loads(process.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - better failure output
        raise AssertionError(f"validator did not emit JSON\nstdout={process.stdout!r}\nstderr={process.stderr!r}") from exc
    return process, output


@pytest.mark.parametrize(
    "name,expected_hash",
    [
        ("control-J.json", "sha256:e4deec4db8638d34214f2b3c02c6a683e9bc1ada7f95abd5f8eed980ffe7346a"),
        ("control-D.json", "sha256:e6c6488166842f95e2adfa063d82840c54ead5ae976bddfbde8d3f1b6f0fbccc"),
        ("control-T.json", "sha256:0da2774a73316f824644cb54683c5c3b3298c928e304b5c45e4b63e604c03ffc"),
        ("control-V-no-result.json", "sha256:880b4bcdb64931b86649f92f96aa8e3f5680bd4c8828146dbc4a898c5548c499"),
        ("JCS-number-small.json", "sha256:90ee420fdf51593d58829af7bb95c273cf5fe573d2a22a735f18f95839cde05b"),
        ("JCS-number-float-one.json", "sha256:668a57097db6ffdab3496efa36ae629a4e15df399b67deae9497ab77dbb258b8"),
        ("JCS-UTF16-order.json", "sha256:13016151730758d682368a5b6c9626e9c541825ed167867afe643a68df235fc7"),
        ("JCS-html-chars.json", "sha256:2263c94c966bd4484e3e2274c18fdbdd98ddaa5388c2a28136914634de25dd18"),
    ],
)
def test_valid_signed_vectors_and_jcs_edges(name: str, expected_hash: str) -> None:
    process, output = run_validator("validate", INTEROP / name, "--keys", KEYS)
    assert process.returncode == 0, process.stderr + process.stdout
    assert output["valid"] is True
    assert output["level"] == 1
    assert output["scopes"] == ["syntax", "cryptographic"]
    assert output["event_hash"] == expected_hash


@pytest.mark.parametrize(
    "name,keys,code,level",
    [
        ("signature-noncanonical-base64url.json", KEYS, "ERR_SIGNATURE_CONTAINER_INVALID", 0),
        ("identity-key-forgery.json", INTEROP / "identity-key-forgery-keys.json", "ERR_SIGNATURE_INVALID", 0),
        ("duplicate-member.json", KEYS, "ERR_DUPLICATE_MEMBER", 0),
        ("J-missing-what.json", KEYS, "ERR_MISSING_REQUIRED_FIELD", 0),
        ("D-missing-details.json", KEYS, "ERR_INVALID_FIELD_TYPE", 0),
        ("invalid-T-missing-target-scope.json", KEYS, "ERR_MISSING_REQUIRED_FIELD", 0),
        ("invalid-V-missing-scope.json", KEYS, "ERR_MISSING_REQUIRED_FIELD", 0),
        ("invalid-V-missing-what.json", KEYS, "ERR_MISSING_REQUIRED_FIELD", 0),
        ("invalid-nonce.json", KEYS, "ERR_INVALID_FIELD_TYPE", 0),
        ("invalid-when-string.json", KEYS, "ERR_INVALID_TIMESTAMP", 0),
        ("invalid-who-number.json", KEYS, "ERR_INVALID_FIELD_TYPE", 0),
        ("unknown-verb.json", KEYS, "ERR_UNKNOWN_VERB", 0),
        ("JOSE-unknown-critical.json", KEYS, "ERR_SIGNATURE_CONTAINER_INVALID", 0),
        ("JEP-unknown-critical-level.json", KEYS, "ERR_UNKNOWN_CRITICAL_EXTENSION", 1),
        ("JEP-known-critical-no-value.json", KEYS, "ERR_EXTENSION_SCHEMA_INVALID", 1),
        ("key-not-found-level.json", INTEROP / "key-not-found-level-keys.json", "ERR_KEY_UNRESOLVED", 0),
        ("key-type-mismatch.json", INTEROP / "key-type-mismatch-keys.json", "ERR_ALG_KEY_TYPE_MISMATCH", 0),
        ("invalid-signature-control.json", KEYS, "ERR_SIGNATURE_INVALID", 0),
    ],
)
def test_exact_failure_code_and_highest_completed_level(
    name: str, keys: Path, code: str, level: int
) -> None:
    process, output = run_validator("validate", INTEROP / name, "--keys", keys)
    assert process.returncode == 1
    assert output["valid"] is False
    assert output["level"] == level
    assert output["errors"][0]["code"] == code


def test_acceptance_mode_enforces_freshness_and_replay(tmp_path: Path) -> None:
    replay_cache = tmp_path / "replay.json"
    args = (
        "validate",
        INTEROP / "control-J.json",
        "--keys",
        KEYS,
        "--mode",
        "acceptance",
        "--now",
        "1788397200",
        "--max-age",
        "300",
        "--max-future-skew",
        "60",
        "--replay-cache",
        replay_cache,
    )
    first_process, first = run_validator(*args)
    second_process, second = run_validator(*args)
    assert first_process.returncode == 0
    assert first["valid"] is True
    assert second_process.returncode == 1
    assert second["valid"] is False
    assert second["level"] == 1
    assert second["errors"][0]["code"] == "ERR_NONCE_REPLAY"


def test_acceptance_mode_requires_persistent_replay_cache() -> None:
    process, output = run_validator(
        "validate",
        INTEROP / "control-J.json",
        "--keys",
        KEYS,
        "--mode",
        "acceptance",
        "--now",
        "1788397200",
    )
    assert process.returncode == 1
    assert output["level"] == 1
    assert output["errors"][0]["code"] == "ERR_DOMAIN_REQUIREMENT_UNSATISFIED"


def test_chain_verifier_reports_level_three_only_after_actor_binding() -> None:
    process, output = run_validator(
        "validate-chain",
        CHAIN,
        "--keys",
        CHAIN_KEYS,
        "--trust-profile",
        "kid-prefix",
        "--log-assumption",
        "partial",
    )
    assert process.returncode == 0, process.stderr + process.stdout
    assert output["valid"] is True
    assert output["level"] == 3
    assert output["log_assumption"] == "partial"
    assert output["event_count"] == 4
    assert "chain_integrity" in output["scopes"]


def test_manifest_suite_checks_exact_assertions() -> None:
    process, output = run_validator("run-tests", ROOT / "test-manifest.json")
    assert process.returncode == 0, process.stderr + process.stdout
    assert output["passed"] == len(output["details"])
    assert output["failed"] == 0
    assert all(item["ok"] for item in output["details"])


def test_manifest_does_not_treat_wrong_failure_as_success(tmp_path: Path) -> None:
    # Regression: the old runner counted any invalid result as a passing invalid
    # vector, even when the test expected a reference failure and validation
    # actually stopped earlier at signature verification.
    manifest = {
        "suite": "fault-isolation-regression",
        "version": "1",
        "cases": [
            {
                "name": "wrong-error-must-fail",
                "kind": "event",
                "path": str(INTEROP / "invalid-signature-control.json"),
                "keys": str(KEYS),
                "expected_valid": False,
                "expected_level": 0,
                "expected_error": "ERR_REF_UNRESOLVED",
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    process, output = run_validator("run-tests", manifest_path)
    assert process.returncode == 1
    assert output["passed"] == 0
    assert output["failed"] == 1
    assert "expected error ERR_REF_UNRESOLVED" in output["details"][0]["checks"][0]


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is not installed")
def test_typescript_seed_agrees_on_core_interop_vectors() -> None:
    built = ROOT / "typescript-validator" / "dist" / "jep_validate.js"
    if not built.exists():
        pytest.skip("TypeScript validator has not been built")
    for name in ["control-J.json", "JCS-number-small.json", "JCS-UTF16-order.json"]:
        process = subprocess.run(
            ["node", str(built), str(INTEROP / name), str(KEYS)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        assert process.returncode == 0, process.stderr + process.stdout
        assert json.loads(process.stdout)["valid"] is True

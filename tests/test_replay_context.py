"""Exercise real signed events against each CLI and a shared replay cache."""

import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def commands(tmp_path_factory):
    result = {"python": [sys.executable, str(ROOT / "reference-validator/jep_validate.py"), "validate"]}
    ts = ROOT / "typescript-validator/dist/jep_validate.js"
    if shutil.which("node") and ts.exists():
        result["typescript"] = [shutil.which("node"), str(ts)]
    if shutil.which("go"):
        binary = tmp_path_factory.mktemp("replay-context") / "validator"
        subprocess.run([shutil.which("go"), "build", "-o", str(binary), "."], cwd=ROOT / "go-validator", check=True)
        result["go"] = [str(binary), "validate"]
    return result


@pytest.fixture
def signed_contexts(tmp_path):
    def b64(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    # The two different contexts had identical delimiter-concatenated keys.
    actors = ["urn:测试:😀\x1fsegment", "urn:测试:😀"]
    audiences = ["urn:app", "segment\x1furn:app"]
    key_path = tmp_path / "keys.json"
    key_path.write_text(json.dumps({"test": {"kty": "OKP", "crv": "Ed25519", "kid": "test", "x": b64(public), "actors": actors}}))
    events = []
    paths = []
    for index, (who, aud) in enumerate(zip(actors, audiences)):
        event = {"jep": "1", "verb": "J", "who": who, "when": 1788397200,
                 "what": {"test": "context separation"}, "aud": aud,
                 "nonce": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}
        protected = b64(b'{"alg":"Ed25519","kid":"test"}')
        signature = private.sign((protected + "." + b64(rfc8785.dumps(event))).encode("ascii"))
        event["sig"] = protected + ".." + b64(signature)
        path = tmp_path / f"event-{index}.json"
        path.write_text(json.dumps(event))
        paths.append(path)
        events.append(event)
    return key_path, paths, events


def validate(command, path, keys, cache):
    key_args = [str(keys)] if "node" in Path(command[0]).name else ["--keys", str(keys)]
    process = subprocess.run(command + [str(path)] + key_args + [
        "--mode", "acceptance", "--trust-profile", "inline", "--now", "1788397200",
        "--replay-cache", str(cache)], capture_output=True, text=True, timeout=30)
    result = json.loads(process.stdout)
    assert process.returncode == (0 if result["valid"] else 1), process.stderr
    return result


@pytest.mark.parametrize("language", ["python", "typescript", "go"])
def test_separate_contexts_accept_once_each(language, commands, signed_contexts, tmp_path):
    if language not in commands:
        pytest.skip(f"{language} validator unavailable")
    keys, paths, _ = signed_contexts
    cache = tmp_path / "cache.json"
    for path in paths:
        assert validate(commands[language], path, keys, cache)["valid"]
    for path in paths:
        result = validate(commands[language], path, keys, cache)
        assert not result["valid"]
        assert result["errors"][0]["code"] == "ERR_NONCE_REPLAY"


@pytest.mark.parametrize("language", ["python", "typescript", "go"])
def test_legacy_cache_still_blocks_consumed_contexts(language, commands, signed_contexts, tmp_path):
    if language not in commands:
        pytest.skip(f"{language} validator unavailable")
    keys, paths, events = signed_contexts
    # Learn the implementation's published profile identifier from a valid result.
    control = validate(commands[language], paths[0], keys, tmp_path / "control.json")
    assert control["valid"]
    event = events[0]
    legacy = "\x1f".join([event["who"], event["aud"], control["profile"], event["nonce"]])
    cache = tmp_path / "legacy.json"
    cache.write_text(json.dumps([legacy]))
    # Old ambiguous entries must fail closed; they cannot safely be split.
    for path in paths:
        result = validate(commands[language], path, keys, cache)
        assert not result["valid"]
        assert result["errors"][0]["code"] == "ERR_NONCE_REPLAY"
    assert json.loads(cache.read_text()) == [legacy]


def test_all_languages_share_unicode_cache_keys(commands, signed_contexts, tmp_path):
    if len(commands) != 3:
        pytest.skip("requires Python, built TypeScript, and Go validators")
    keys, paths, _ = signed_contexts
    for producer, command in commands.items():
        cache = tmp_path / f"{producer}.json"
        assert validate(command, paths[0], keys, cache)["valid"]
        for consumer in commands.values():
            result = validate(consumer, paths[0], keys, cache)
            assert not result["valid"]
            assert result["errors"][0]["code"] == "ERR_NONCE_REPLAY"
        assert validate(command, paths[1], keys, cache)["valid"]
        assert len(json.loads(cache.read_text())) == 2

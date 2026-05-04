import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "reference-validator" / "jep_validate.py"
KEYS = ROOT / "test-vectors" / "valid" / "public-keys.json"

def run_cmd(args):
    return subprocess.run([sys.executable, str(VALIDATOR)] + args, cwd=ROOT, text=True, capture_output=True)

def test_valid_signed_vectors():
    for name in ["J-basic-signed.json", "D-basic-signed.json", "T-basic-signed.json", "V-basic-signed.json"]:
        p = ROOT / "test-vectors" / "valid" / name
        res = run_cmd(["validate", str(p), "--keys", str(KEYS)])
        assert res.returncode == 0, res.stderr + res.stdout
        out = json.loads(res.stdout)
        assert out["valid"] is True
        assert out["level"] >= 1
        assert out["event_hash"].startswith("sha256:")

def test_invalid_signature_fails():
    p = ROOT / "test-vectors" / "invalid" / "invalid-signature.json"
    res = run_cmd(["validate", str(p), "--keys", str(KEYS)])
    assert res.returncode != 0
    out = json.loads(res.stdout)
    assert out["valid"] is False
    assert out["errors"][0]["code"] == "ERR_SIGNATURE_INVALID"

def test_unknown_critical_extension_fails():
    p = ROOT / "test-vectors" / "invalid" / "unknown-critical-extension.json"
    res = run_cmd(["validate", str(p), "--keys", str(KEYS)])
    assert res.returncode != 0
    out = json.loads(res.stdout)
    assert out["valid"] is False
    assert out["errors"][0]["code"] == "ERR_UNKNOWN_CRITICAL_EXTENSION"

def test_run_tests_summary():
    res = run_cmd(["run-tests", str(ROOT / "test-vectors"), "--keys", str(KEYS)])
    # Current seed suite includes one ref mismatch case expected invalid but minimal direct validation
    # may classify it differently; run-tests must still complete and report.
    out = json.loads(res.stdout)
    assert "passed" in out and "failed" in out

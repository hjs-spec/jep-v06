import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "test-vectors" / "interop"


def test_python_and_typescript_consumption_is_atomic(tmp_path):
    ts = ROOT / "typescript-validator" / "dist" / "jep_validate.js"
    node = shutil.which("node")
    commands = [[sys.executable, str(ROOT / "reference-validator" / "jep_validate.py"), "validate",
                 str(VECTORS / "control-J.json"), "--keys", str(VECTORS / "public-keys.json")]]
    if ts.exists() and node:
        commands.append([node, str(ts), str(VECTORS / "control-J.json"), str(VECTORS / "public-keys.json")])
    extra = ["--mode", "acceptance", "--now", "1788397200", "--replay-cache", str(tmp_path / "cache.json")]
    def run(i):
        process = subprocess.run(commands[i % len(commands)] + extra, capture_output=True, text=True, timeout=30)
        return json.loads(process.stdout)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(run, range(16)))
    assert sum(result["valid"] for result in results) == 1
    assert all(result["valid"] or result["errors"][0]["code"] in {"ERR_NONCE_REPLAY", "ERR_DOMAIN_REQUIREMENT_UNSATISFIED"} for result in results)


def test_unavailable_replay_storage_fails_closed(tmp_path):
    from test_reference_validator import run_validator
    cache = tmp_path / "cache.json"
    (tmp_path / "cache.json.consume-lock").mkdir()
    process, result = run_validator("validate", VECTORS / "control-J.json", "--keys", VECTORS / "public-keys.json",
                                    "--mode", "acceptance", "--now", "1788397200", "--replay-cache", cache)
    assert process.returncode == 1
    assert not result["valid"]
    assert result["errors"][0]["code"] == "ERR_DOMAIN_REQUIREMENT_UNSATISFIED"
    assert not cache.exists()

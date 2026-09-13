"""Cross-repository smoke test. Requires sibling API, SDKs and built JS/TS projects.

Run: python integration/verify_workspace.py --workspace /path/to/hjs-spec
Only loopback HTTP and temporary state are used; no credentials are needed.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


def command(args, **kwargs):
    result = subprocess.run(
        [str(arg) for arg in args], capture_output=True, text=True, timeout=90, **kwargs
    )
    if result.returncode:
        raise AssertionError(
            f"Command failed: {args}\n{result.stdout}\n{result.stderr}"
        )
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workspace", type=Path, default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    node, go = shutil.which("node"), shutil.which("go")
    if not node or not go:
        raise RuntimeError("node and go must be on PATH")
    sys.path.insert(0, str(workspace / "sdk-py"))
    from jep.client import JEPClient, VerifyEventRequest
    import rfc8785
    import hashlib

    with tempfile.TemporaryDirectory(prefix="jep-integration-") as directory:
        temporary = Path(directory)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        environment = dict(
            os.environ,
            JEP_STATE_DIR=str(temporary / "state"),
            PYTHONDONTWRITEBYTECODE="1",
        )

        def start():
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                cwd=workspace / "jep-api",
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for _ in range(160):
                if process.poll() is not None:
                    raise RuntimeError("API exited during startup")
                try:
                    with urllib.request.urlopen(
                        url + "/health", timeout=0.2
                    ) as response:
                        if response.status == 200:
                            return process
                except OSError:
                    time.sleep(0.05)
            process.terminate()
            process.wait(timeout=10)
            raise RuntimeError("API did not start")

        server = start()
        try:
            client = JEPClient(base_url=url)
            requests = [
                {"verb": "J", "what": {"claim": "start", "\ue000": 1.0, "😀": 1e-7}},
                {
                    "verb": "D",
                    "what": {
                        "claim": "delegate",
                        "delegatee": "worker",
                        "scope": ["read"],
                    },
                },
                {
                    "verb": "T",
                    "what": {
                        "claim": "terminate",
                        "target": "worker",
                        "termination_scope": "delegation",
                    },
                },
                {
                    "verb": "V",
                    "what": {"verification_scope": ["syntax", "cryptographic"]},
                },
            ]
            events = []
            parent = None
            for request in requests:
                if parent:
                    request["ref"] = {
                        "type": "jep-event",
                        "value": parent,
                        "hash": parent,
                    }
                request.update(who="integration:actor", aud="integration:receiver")
                created = client.create_event(request)
                event = created.event.to_dict()
                assert client.verify_event(VerifyEventRequest(created.event)).valid
                assert (
                    created.event_hash
                    == "sha256:" + hashlib.sha256(rfc8785.dumps(event)).hexdigest()
                )
                parent = created.event_hash
                events.append(event)
            event_file = temporary / "events.json"
            event_file.write_text(json.dumps(events, ensure_ascii=False))
            requests_file = temporary / "requests.json"
            requests_file.write_text(json.dumps(requests, ensure_ascii=False))
            # Use the actual JavaScript client against the API for all four verbs.
            js = temporary / "sdk.mjs"
            js.write_text(
                "import {JEPClient} from "
                + json.dumps((workspace / "sdk-js/src/index.js").as_uri())
                + ";\n"
                + """
import fs from 'node:fs';
const client = new JEPClient({baseUrl:process.argv[2]});
for (const request of JSON.parse(fs.readFileSync(process.argv[3], 'utf8'))) {
  const created = await client.createEvent(request);
  const result = await client.verifyEvent({event:created.event});
  if (result.valid !== true) throw new Error(JSON.stringify(result));
}
console.log('JS J/D/T/V passed');
"""
            )
            command([node, js, url, requests_file])
            # Go decoding and re-encoding must retain every signed member.
            source = temporary / "roundtrip.go"
            source.write_text("""package main
import ("encoding/json"; "os"; jep "github.com/hjs-spec/jep-sdk-go")
func main() {
 var events []jep.JEPEvent
 if err := json.NewDecoder(os.Stdin).Decode(&events); err != nil { panic(err) }
 client := jep.NewClientWithURL(os.Args[1], "")
 for _, event := range events {
  result, err := client.VerifyEvent(&jep.VerifyEventRequest{Event:event, Mode:"archival"})
  if err != nil { panic(err) }; if !result.Valid { panic("Go roundtrip failed verification") }
 }
 if err := json.NewEncoder(os.Stdout).Encode(events); err != nil { panic(err) }
}
""")
            roundtrip = json.loads(
                command(
                    [go, "run", source, url],
                    cwd=workspace / "sdk-go",
                    input=event_file.read_text(),
                )
            )
            assert roundtrip == events
            # Both reference validators consume the API's exact signed payloads.
            with urllib.request.urlopen(url) as response:
                public_key = json.load(response)["public_key"]
            keys = temporary / "keys.json"
            keys.write_text(json.dumps({public_key["kid"]: public_key}))
            for index, event in enumerate(events):
                path = temporary / f"event-{index}.json"
                path.write_text(json.dumps(event, ensure_ascii=False))
                py = json.loads(
                    command(
                        [
                            sys.executable,
                            workspace / "jep-v06/reference-validator/jep_validate.py",
                            "validate",
                            path,
                            "--keys",
                            keys,
                        ]
                    )
                )
                ts = json.loads(
                    command(
                        [
                            node,
                            workspace
                            / "jep-v06/typescript-validator/dist/jep_validate.js",
                            path,
                            keys,
                        ]
                    )
                )
                assert (
                    py["valid"] and ts["valid"] and py["event_hash"] == ts["event_hash"]
                )
            # Run the committed action entry point as an actual packaged action.
            action_env = dict(
                environment,
                GITHUB_REPOSITORY="test/repo",
                GITHUB_ACTOR="integration",
                GITHUB_EVENT_NAME="workflow_dispatch",
                GITHUB_WORKFLOW="test",
                GITHUB_RUN_ID="1",
                GITHUB_SHA="a" * 40,
                GITHUB_REF="refs/heads/main",
                INPUT_MODE="api",
                INPUT_JEP_API_URL=url,
                INPUT_UPLOAD_ARTIFACT="false",
            )
            standalone = temporary / "action.mjs"
            shutil.copyfile(workspace / "jep-github-action/dist/index.mjs", standalone)
            command([node, standalone], cwd=temporary, env=action_env)
            artifact = json.loads((temporary / "jep-event-artifact.json").read_text())
            assert artifact["validation"]["valid"] is True
            # Restart must preserve the key, old signatures, and consumed nonces.
            accepted = client.verify_event(
                VerifyEventRequest(
                    events[0],
                    mode="acceptance",
                    expected_audience="integration:receiver",
                )
            )
            assert accepted.valid
            server.terminate()
            server.wait(timeout=10)
            server = start()
            assert client.verify_event(VerifyEventRequest(events[0])).valid
            replay = client.verify_event(
                VerifyEventRequest(
                    events[0],
                    mode="acceptance",
                    expected_audience="integration:receiver",
                )
            )
            assert not replay.valid and replay.errors[0]["code"] == "ERR_NONCE_REPLAY"
            print(
                json.dumps(
                    {
                        "sdk_verb_checks": 12,
                        "reference_validator_checks": 8,
                        "packaged_action": "passed",
                        "restart_and_replay": "passed",
                    }
                )
            )
        finally:
            server.terminate()
            server.wait(timeout=10)


if __name__ == "__main__":
    main()

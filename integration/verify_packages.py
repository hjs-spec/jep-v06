"""Installed-package regression test; creates no external events or deployments."""

import argparse
import hashlib
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

parser = argparse.ArgumentParser(
    description="Exercise installed Python/JS SDK artifacts and a Go module against a temporary local API."
)
parser.add_argument(
    "--workspace", type=Path, default=Path(__file__).resolve().parents[2]
)
parser.add_argument("--python-wheel", type=Path, required=True)
parser.add_argument("--javascript-tarball", type=Path, required=True)
parser.add_argument(
    "--go-version", help="Released Go module version; default uses the sibling checkout"
)
args = parser.parse_args()
WORK = args.workspace.resolve()
GO = shutil.which("go")
if not GO:
    raise RuntimeError("go must be on PATH")


def run(args, **kwargs):
    result = subprocess.run(
        [str(a) for a in args], capture_output=True, text=True, timeout=120, **kwargs
    )
    if result.returncode:
        raise RuntimeError(result.stdout + "\n" + result.stderr)
    return result.stdout


with tempfile.TemporaryDirectory(prefix="jep-released-sdk-audit-") as directory:
    temp = Path(directory)
    target = temp / "python"
    wheel = args.python_wheel.resolve()
    run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--target", target, wheel]
    )
    sys.path.insert(0, str(target))
    from jep import JEPClient, VerifyEventRequest
    import jep
    import rfc8785

    assert str(target) in jep.__file__
    run(
        [
            "npm",
            "install",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            args.javascript_tarball.resolve(),
        ],
        cwd=temp,
    )
    (temp / "go.mod").write_text(
        "module sdk-audit\n\ngo 1.21\n\nrequire github.com/hjs-spec/sdk-go "
        + (args.go_version or "v0.0.0")
        + "\n"
        + (
            ""
            if args.go_version
            else "replace github.com/hjs-spec/sdk-go => "
            + json.dumps(str(WORK / "sdk-go"))
            + "\n"
        )
    )
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    token = "local-audit-only"
    token_path = temp / "signing-token"
    token_path.write_text(token)
    env = dict(
        os.environ,
        JEP_STATE_DIR=str(temp / "state"),
        JEP_SIGNING_TOKEN_FILE=str(token_path),
    )
    server = subprocess.Popen(
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
        cwd=WORK / "jep-api",
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if server.poll() is not None:
                raise RuntimeError("API exited")
            try:
                urllib.request.urlopen(url + "/health", timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        claims = [
            {"verb": "J", "what": {"claim": "start", "😀": 1e-7, "\ue000": 1.0}},
            {
                "verb": "D",
                "what": {"claim": "delegate", "delegatee": "worker", "scope": ["read"]},
            },
            {
                "verb": "T",
                "what": {
                    "claim": "terminate",
                    "target": "worker",
                    "termination_scope": "delegation",
                },
            },
            {"verb": "V", "what": {"verification_scope": ["syntax", "cryptographic"]}},
        ]
        (temp / "requests.json").write_text(json.dumps(claims, ensure_ascii=False))
        client = JEPClient(base_url=url, api_key=token)
        parent = None
        py_events = []
        for case in claims:
            request = dict(case, who="audit:python", aud="audit:receiver")
            if parent:
                request["ref"] = parent
            created = client.create_event(request)
            event = created.event.to_dict()
            result = client.verify_event(VerifyEventRequest(created.event))
            assert (
                result.valid
                and result.conformance_class == "JEP-Baseline-Ed25519-JWS-JCS-0.6"
            )
            assert created.validation.conformance_class == result.conformance_class
            assert all("level" in w and "recoverable" in w for w in result.warnings)
            assert (
                created.event_hash
                == "sha256:" + hashlib.sha256(rfc8785.dumps(event)).hexdigest()
            )
            parent = created.event_hash
            py_events.append(event)
        js = temp / "audit.mjs"
        js.write_text("""import fs from 'node:fs';
import {JEPClient} from '@hjs-spec/jep-sdk-js';
const client = new JEPClient({baseUrl:process.argv[2],apiKey:'local-audit-only'});
let parent; const events=[];
for(const item of JSON.parse(fs.readFileSync(process.argv[3],'utf8'))) {
 const request={...item,who:'audit:javascript',aud:'audit:receiver'};
 if(parent)request.ref=parent;
 const created=await client.createEvent(request);
 const result=await client.verifyEvent({event:created.event});
 if(!result.valid || result.conformance_class !== 'JEP-Baseline-Ed25519-JWS-JCS-0.6' || created.validation.conformance_class !== result.conformance_class)throw new Error(JSON.stringify(result));
 if(result.warnings.some(w => !('level' in w) || !('recoverable' in w)))throw new Error('incomplete diagnostic');
 parent=created.event_hash; events.push(created.event);
}
console.log(JSON.stringify(events));
""")
        js_events = json.loads(run(["node", js, url, temp / "requests.json"], cwd=temp))
        source = temp / "audit.go"
        source.write_text("""package main
import("encoding/json";"os";jep "github.com/hjs-spec/sdk-go")
func main(){
 var requests []jep.CreateEventRequest
 file,err:=os.Open(os.Args[2]);if err!=nil{panic(err)};defer file.Close()
 decoder:=json.NewDecoder(file);decoder.UseNumber()
 if err:=decoder.Decode(&requests);err!=nil{panic(err)}
 client:=jep.NewClientWithURL(os.Args[1],"local-audit-only")
 parent:="";events:=[]jep.JEPEvent{}
 for _,request:=range requests{
  request.Who="audit:go";request.Aud="audit:receiver"
  if parent!=""{ref:=parent;request.Ref=&ref}
  created,err:=client.CreateEvent(&request);if err!=nil{panic(err)}
  result,err:=client.VerifyEvent(&jep.VerifyEventRequest{Event:created.Event,Mode:"archival"})
  if err!=nil{panic(err)};if !result.Valid || result.ConformanceClass!="JEP-Baseline-Ed25519-JWS-JCS-0.6" || created.Validation.ConformanceClass!=result.ConformanceClass{panic("invalid roundtrip/conformance class")}
  for _,w:=range result.Warnings{if _,ok:=w["level"];!ok{panic("missing warning level")};if _,ok:=w["recoverable"];!ok{panic("missing recoverable")}}
  parent=created.EventHash;events=append(events,created.Event)
 }
 if err:=json.NewEncoder(os.Stdout).Encode(events);err!=nil{panic(err)}
}
""")
        go_events = json.loads(
            run([GO, "run", "-mod=mod", source, url, temp / "requests.json"], cwd=temp)
        )
        for event in js_events + go_events:
            result = client.verify_event(VerifyEventRequest(event))
            assert result.valid
            assert (
                result.event_hash
                == "sha256:" + hashlib.sha256(rfc8785.dumps(event)).hexdigest()
            )
        summary = {
            "api_protocol_profile": "jep-core-0.6",
            "packages": {
                "python": wheel.name,
                "javascript": args.javascript_tarball.name,
                "go": args.go_version or "sibling checkout",
            },
            "create_and_verify": {
                "python": len(py_events),
                "javascript": len(js_events),
                "go": len(go_events),
            },
            "cross_sdk_verification": len(js_events) + len(go_events),
            "event_hash_checks": 12,
        }
        print(json.dumps(summary))
    finally:
        server.terminate()
        server.wait(timeout=10)

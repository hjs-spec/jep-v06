#!/usr/bin/env node
/**
 * JEP v0.6 TypeScript validator seed.
 *
 * Features:
 * - required field checks
 * - JCS-compatible canonicalization for seed vectors
 * - event hash calculation
 * - detached JWS Compact parsing
 * - Ed25519 verification using Node crypto when available
 * - unknown critical extension rejection
 *
 * This is an interoperability seed, not a production validator.
 */

import * as fs from "fs";
import * as crypto from "crypto";

const KNOWN_EXTENSIONS = new Set([
  "https://jep.org/priv/digest-only",
  "https://jep.org/multisig",
  "https://jep.org/ttl",
  "https://jep.org/storage",
  "https://jep.org/subject",
  "https://jep.org/crypto/profile",
]);

function b64uDecode(s: string): Buffer {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64");
}

function b64u(data: Buffer | string): string {
  return Buffer.from(data).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function canonicalize(value: any): string {
  if (value === null) return "null";
  if (typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
}

function eventHash(event: any): string {
  return "sha256:" + crypto.createHash("sha256").update(Buffer.from(canonicalize(event), "utf8")).digest("hex");
}

function result(valid: boolean, level: number, eventHash: string | null, code?: string, message?: string) {
  return {
    valid,
    level,
    mode: "archival",
    profile: "jep-core-0.6",
    scopes: valid ? ["syntax", "cryptographic"] : [],
    event_hash: eventHash,
    warnings: [],
    errors: code ? [{ code, message, level, recoverable: false }] : []
  };
}

function loadKeys(path?: string): Map<string, any> {
  const map = new Map<string, any>();
  if (!path) return map;
  const data = JSON.parse(fs.readFileSync(path, "utf8"));
  for (const k of Object.keys(data)) {
    if (data[k].kid) map.set(data[k].kid, data[k]);
  }
  return map;
}

function verifyDetachedJws(event: any, payload: string, keys: Map<string, any>): {ok: boolean, code?: string, message?: string} {
  if (typeof event.sig !== "string" || event.sig.split(".").length !== 3) {
    return {ok:false, code:"ERR_SIGNATURE_CONTAINER_INVALID", message:"sig is not detached compact JWS"};
  }
  const [protectedB64, empty, sigB64] = event.sig.split(".");
  if (empty !== "") return {ok:false, code:"ERR_SIGNATURE_CONTAINER_INVALID", message:"payload segment must be empty"};
  const header = JSON.parse(b64uDecode(protectedB64).toString("utf8"));
  if (header.alg !== "Ed25519") return {ok:false, code:"ERR_UNSUPPORTED_SIGNATURE_ALG", message:`Unsupported alg: ${header.alg}`};
  const jwk = keys.get(header.kid);
  if (!jwk) return {ok:false, code:"ERR_KEY_UNRESOLVED", message:`No key for kid: ${header.kid}`};

  try {
    // Node supports Ed25519 verification using KeyObject created from JWK in modern versions.
    const keyObj = crypto.createPublicKey({key: jwk, format: "jwk"});
    const signingInput = Buffer.from(protectedB64 + "." + b64u(Buffer.from(payload, "utf8")), "ascii");
    const sig = b64uDecode(sigB64);
    const ok = crypto.verify(null, signingInput, keyObj, sig);
    return ok ? {ok:true} : {ok:false, code:"ERR_SIGNATURE_INVALID", message:"Ed25519 signature verification failed"};
  } catch (e: any) {
    return {ok:false, code:"ERR_SIGNATURE_INVALID", message:String(e?.message || e)};
  }
}

function validate(event: any, keys: Map<string, any>) {
  for (const f of ["jep","verb","who","when","nonce","sig"]) {
    if (!(f in event)) return result(false, 0, null, "ERR_MISSING_REQUIRED_FIELD", `Missing ${f}`);
  }
  if (event.jep !== "1") return result(false, 0, null, "ERR_UNSUPPORTED_JEP_VERSION", "jep must be '1'");
  if (!["J","D","T","V"].includes(event.verb)) return result(false, 0, null, "ERR_UNKNOWN_VERB", "verb must be J/D/T/V");
  if (typeof event.when !== "number") return result(false, 0, null, "ERR_INVALID_TIMESTAMP", "when must be integer");

  const h = eventHash(event);
  const unsigned = {...event};
  delete unsigned.sig;
  const payload = canonicalize(unsigned);

  const ver = verifyDetachedJws(event, payload, keys);
  if (!ver.ok) return result(false, ver.code === "ERR_KEY_UNRESOLVED" ? 1 : 0, h, ver.code, ver.message);

  for (const ext of event.ext_crit || []) {
    if (!KNOWN_EXTENSIONS.has(ext)) {
      return result(false, 2, h, "ERR_UNKNOWN_CRITICAL_EXTENSION", `Unknown critical extension: ${ext}`);
    }
  }
  return result(true, 1, h);
}

const file = process.argv[2];
const keysPath = process.argv[3];
if (!file) {
  console.error("usage: node dist/jep_validate.js <event-or-vector.json> [public-keys.json]");
  process.exit(2);
}
const data = JSON.parse(fs.readFileSync(file, "utf8"));
const event = data.event || data;
const out = validate(event, loadKeys(keysPath));
console.log(JSON.stringify(out, null, 2));
process.exit(out.valid ? 0 : 1);

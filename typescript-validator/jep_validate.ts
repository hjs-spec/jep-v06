#!/usr/bin/env node
/**
 * JEP v0.6 TypeScript validator seed.
 *
 * Implements JEP-Core Level 0 and the Ed25519/JWS/JCS Level 1 baseline,
 * with optional local actor binding and acceptance-mode replay/freshness
 * checks. It does not make legal, policy, factual, or authorization claims.
 */

import * as fs from "fs";
import * as crypto from "crypto";

const CORE_PROFILE = "jep-core-0.6";
const BASELINE_CLASS = "JEP-Baseline-Ed25519-JWS-JCS-0.6";
const TOP_LEVEL_FIELDS = new Set([
  "jep", "verb", "who", "when", "what", "nonce", "aud", "ref", "ext", "ext_crit", "sig",
]);
const VERBS = new Set(["J", "D", "T", "V"]);
const DIGEST_RE = /^[a-z0-9][a-z0-9-]*:[0-9a-f]+$/;
const B64U_RE = /^[A-Za-z0-9_-]*$/;
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

class ValidationFault extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly failedLevel: number,
    public readonly recoverable = false,
  ) {
    super(message);
  }

  toJSON() {
    return { code: this.code, message: this.message, level: this.failedLevel, recoverable: this.recoverable };
  }
}

/** Strict JSON scanner used to detect duplicate object member names before JSON.parse loses them. */
class JsonScanner {
  private pos = 0;
  constructor(private readonly text: string) {}

  parse(): void {
    this.skipWs();
    this.parseValue();
    this.skipWs();
    if (this.pos !== this.text.length) throw new Error(`unexpected trailing data at ${this.pos}`);
  }

  private skipWs(): void {
    while (this.pos < this.text.length && /[\x20\x09\x0a\x0d]/.test(this.text[this.pos])) this.pos++;
  }

  private parseValue(): void {
    this.skipWs();
    const ch = this.text[this.pos];
    if (ch === "{") return this.parseObject();
    if (ch === "[") return this.parseArray();
    if (ch === '"') { this.parseString(); return; }
    if (ch === "t") return this.literal("true");
    if (ch === "f") return this.literal("false");
    if (ch === "n") return this.literal("null");
    this.parseNumber();
  }

  private parseObject(): void {
    this.expect("{");
    this.skipWs();
    const seen = new Set<string>();
    if (this.peek("}")) { this.pos++; return; }
    while (true) {
      this.skipWs();
      if (!this.peek('"')) throw new Error(`expected object member name at ${this.pos}`);
      const key = this.parseString();
      if (seen.has(key)) throw new ValidationFault("ERR_DUPLICATE_MEMBER", `duplicate JSON member: ${key}`, 0);
      seen.add(key);
      this.skipWs();
      this.expect(":");
      this.parseValue();
      this.skipWs();
      if (this.peek("}")) { this.pos++; return; }
      this.expect(",");
    }
  }

  private parseArray(): void {
    this.expect("[");
    this.skipWs();
    if (this.peek("]")) { this.pos++; return; }
    while (true) {
      this.parseValue();
      this.skipWs();
      if (this.peek("]")) { this.pos++; return; }
      this.expect(",");
    }
  }

  private parseString(): string {
    const start = this.pos;
    this.expect('"');
    while (this.pos < this.text.length) {
      const ch = this.text[this.pos++];
      if (ch === '"') {
        const raw = this.text.slice(start, this.pos);
        return JSON.parse(raw);
      }
      if (ch === "\\") {
        if (this.pos >= this.text.length) throw new Error("unterminated JSON escape");
        const esc = this.text[this.pos++];
        if (esc === "u") {
          const hex = this.text.slice(this.pos, this.pos + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error(`invalid Unicode escape at ${this.pos}`);
          this.pos += 4;
        } else if (!'"\\/bfnrt'.includes(esc)) {
          throw new Error(`invalid JSON escape \\${esc}`);
        }
      } else if (ch.charCodeAt(0) <= 0x1f) {
        throw new Error("unescaped control character in JSON string");
      }
    }
    throw new Error("unterminated JSON string");
  }

  private parseNumber(): void {
    const match = this.text.slice(this.pos).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) throw new Error(`invalid JSON value at ${this.pos}`);
    this.pos += match[0].length;
  }

  private literal(value: string): void {
    if (this.text.slice(this.pos, this.pos + value.length) !== value) throw new Error(`invalid JSON literal at ${this.pos}`);
    this.pos += value.length;
  }

  private expect(value: string): void {
    if (!this.peek(value)) throw new Error(`expected ${JSON.stringify(value)} at ${this.pos}`);
    this.pos += value.length;
  }

  private peek(value: string): boolean { return this.text.startsWith(value, this.pos); }
}

function loadJsonUnique(path: string): any {
  let text: string;
  try { text = UTF8_DECODER.decode(fs.readFileSync(path)); }
  catch (e: any) { throw new ValidationFault("ERR_INVALID_JSON", `JSON is not valid UTF-8: ${String(e?.message || e)}`, 0); }
  try {
    new JsonScanner(text).parse();
    const value = JSON.parse(text);
    validateIJson(value, "$");
    return value;
  } catch (e: any) {
    if (e instanceof ValidationFault) throw e;
    throw new ValidationFault("ERR_INVALID_JSON", `invalid JSON: ${String(e?.message || e)}`, 0);
  }
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 >= value.length) return true;
      const next = value.charCodeAt(++i);
      if (next < 0xdc00 || next > 0xdfff) return true;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}

function validateIJson(value: any, path: string): void {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`${path}: non-finite number is not I-JSON`);
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) throw new Error(`${path}: integer exceeds the interoperable IEEE-754 safe range`);
    return;
  }
  if (typeof value === "string") {
    if (hasUnpairedSurrogate(value)) throw new Error(`${path}: string contains an unpaired surrogate`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => validateIJson(item, `${path}[${index}]`));
    return;
  }
  if (typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (hasUnpairedSurrogate(key)) throw new Error(`${path}: member name contains an unpaired surrogate`);
      validateIJson(item, `${path}.${key}`);
    }
    return;
  }
  throw new Error(`${path}: unsupported JSON type`);
}

/** RFC 8785 serialization using ECMAScript primitive serialization and UTF-16 key order. */
function canonicalize(value: any): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new ValidationFault("ERR_CANONICALIZATION_FAILED", "non-finite number", 1);
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    if (hasUnpairedSurrogate(value)) throw new ValidationFault("ERR_CANONICALIZATION_FAILED", "unpaired surrogate", 1);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort(); // ECMAScript sort is UTF-16 code-unit order.
    return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new ValidationFault("ERR_CANONICALIZATION_FAILED", `unsupported type: ${typeof value}`, 1);
}

function b64u(data: Buffer | string): string {
  return Buffer.from(data).toString("base64url");
}

function b64uDecode(value: unknown, label: string): Buffer {
  if (typeof value !== "string" || !B64U_RE.test(value)) {
    throw new ValidationFault("ERR_SIGNATURE_CONTAINER_INVALID", `${label} is not unpadded base64url`, 1);
  }
  try { return Buffer.from(value, "base64url"); }
  catch (e: any) { throw new ValidationFault("ERR_SIGNATURE_CONTAINER_INVALID", `invalid ${label}: ${String(e?.message || e)}`, 1); }
}

function eventHash(event: any): string {
  return `sha256:${crypto.createHash("sha256").update(Buffer.from(canonicalize(event), "utf8")).digest("hex")}`;
}

function requireCondition(condition: boolean, code: string, message: string, level = 0): asserts condition {
  if (!condition) throw new ValidationFault(code, message, level);
}

function validateDigest(value: unknown, field: string): void {
  requireCondition(typeof value === "string" && DIGEST_RE.test(value), "ERR_INVALID_FIELD_TYPE", `${field} must be an algorithm-tagged lowercase hexadecimal digest`);
  const [algorithm, digest] = value.split(":", 2);
  if (algorithm === "sha256") requireCondition(digest.length === 64, "ERR_INVALID_FIELD_TYPE", `${field} sha256 digest must contain 64 hex characters`);
}

function validateWhat(value: any): void {
  if (typeof value === "string") return validateDigest(value, "what");
  requireCondition(value !== null && typeof value === "object" && !Array.isArray(value), "ERR_INVALID_FIELD_TYPE", "what must be an object or digest");
  requireCondition(Object.keys(value).length > 0, "ERR_INVALID_FIELD_TYPE", "what object must not be empty");
  if ("claim" in value) requireCondition(typeof value.claim === "string" && value.claim.length > 0, "ERR_INVALID_FIELD_TYPE", "what.claim must be a non-empty string");
}

function validateRef(value: any, allowNull = true): void {
  if (value === null) {
    requireCondition(allowNull, "ERR_MISSING_REQUIRED_FIELD", "ref must not be null");
    return;
  }
  if (typeof value === "string") return validateDigest(value, "ref");
  requireCondition(value && typeof value === "object" && !Array.isArray(value), "ERR_INVALID_FIELD_TYPE", "ref must be null, a digest, or a typed object");
  requireCondition("type" in value && "value" in value, "ERR_MISSING_REQUIRED_FIELD", "ref object requires type and value");
  requireCondition(typeof value.type === "string" && value.type.length > 0, "ERR_INVALID_FIELD_TYPE", "ref.type must be a non-empty string");
  if ("hash" in value) validateDigest(value.hash, "ref.hash");
}

function validateShape(event: any): void {
  requireCondition(event && typeof event === "object" && !Array.isArray(event), "ERR_INVALID_FIELD_TYPE", "JEP event must be an object");
  const unknown = Object.keys(event).filter(key => !TOP_LEVEL_FIELDS.has(key)).sort();
  requireCondition(unknown.length === 0, "ERR_INVALID_FIELD_TYPE", `unknown top-level member(s): ${unknown.join(", ")}; use ext`);
  for (const field of ["jep", "verb", "who", "when", "nonce"]) {
    requireCondition(field in event, "ERR_MISSING_REQUIRED_FIELD", `missing required field: ${field}`);
  }
  if (!("sig" in event)) throw new ValidationFault("ERR_SIGNATURE_MISSING", "missing required field: sig", 1);
  requireCondition(event.jep === "1", "ERR_UNSUPPORTED_JEP_VERSION", "jep must be '1'");
  requireCondition(typeof event.verb === "string", "ERR_INVALID_FIELD_TYPE", "verb must be a string");
  requireCondition(VERBS.has(event.verb), "ERR_UNKNOWN_VERB", "verb must be J/D/T/V");
  requireCondition(typeof event.who === "string" && event.who.length > 0, "ERR_INVALID_FIELD_TYPE", "who must be a non-empty string");
  requireCondition(Number.isInteger(event.when), "ERR_INVALID_TIMESTAMP", "when must be an integer Unix timestamp");
  requireCondition(typeof event.nonce === "string" && UUID_V4_RE.test(event.nonce), "ERR_INVALID_FIELD_TYPE", "nonce must be a canonical UUIDv4 string");
  requireCondition(typeof event.sig === "string" && event.sig.length > 0, "ERR_SIGNATURE_CONTAINER_INVALID", "baseline sig must be a detached compact JWS string", 1);
  if ("aud" in event) requireCondition(typeof event.aud === "string" && event.aud.length > 0, "ERR_INVALID_FIELD_TYPE", "aud must be a non-empty string");
  if ("ref" in event) validateRef(event.ref);
  if ("ext" in event) {
    requireCondition(event.ext && typeof event.ext === "object" && !Array.isArray(event.ext), "ERR_INVALID_FIELD_TYPE", "ext must be an object");
    for (const [id, value] of Object.entries(event.ext)) requireCondition(id.length > 0 && value !== null && typeof value === "object" && !Array.isArray(value), "ERR_INVALID_FIELD_TYPE", `extension ${id} must contain an object`);
  }
  if ("ext_crit" in event) {
    requireCondition(Array.isArray(event.ext_crit), "ERR_INVALID_FIELD_TYPE", "ext_crit must be an array");
    requireCondition(event.ext_crit.every((x: any) => typeof x === "string" && x.length > 0), "ERR_INVALID_FIELD_TYPE", "ext_crit entries must be non-empty strings");
    requireCondition(new Set(event.ext_crit).size === event.ext_crit.length, "ERR_INVALID_FIELD_TYPE", "ext_crit entries must be unique");
  }

  requireCondition("what" in event && event.what !== null, "ERR_MISSING_REQUIRED_FIELD", `${event.verb} events require non-null what`);
  validateWhat(event.what);
  if (event.verb === "D") {
    requireCondition("ref" in event, "ERR_MISSING_REQUIRED_FIELD", "D events require ref in the v0.6 baseline shape");
    if (typeof event.what === "object") {
      for (const field of ["claim", "delegatee", "scope"]) requireCondition(field in event.what, "ERR_MISSING_REQUIRED_FIELD", `D event requires what.${field}`);
      requireCondition(typeof event.what.delegatee === "string" && event.what.delegatee.length > 0, "ERR_INVALID_FIELD_TYPE", "what.delegatee must be a non-empty string");
      requireCondition(event.what.scope !== null, "ERR_INVALID_FIELD_TYPE", "what.scope must not be null");
    }
  } else if (event.verb === "T") {
    requireCondition("ref" in event, "ERR_MISSING_REQUIRED_FIELD", "T events require ref in the v0.6 baseline shape");
    if (typeof event.what === "object") {
      for (const field of ["claim", "target", "termination_scope"]) requireCondition(field in event.what, "ERR_MISSING_REQUIRED_FIELD", `T event requires what.${field}`);
      requireCondition(event.what.target !== null, "ERR_INVALID_FIELD_TYPE", "what.target must not be null");
      requireCondition(typeof event.what.termination_scope === "string" && event.what.termination_scope.length > 0, "ERR_INVALID_FIELD_TYPE", "what.termination_scope must be a non-empty string");
    }
  } else if (event.verb === "V") {
    requireCondition("ref" in event && event.ref !== null, "ERR_MISSING_REQUIRED_FIELD", "V events require non-null ref");
    if (typeof event.what === "object") {
      requireCondition("verification_scope" in event.what, "ERR_MISSING_REQUIRED_FIELD", "V event requires what.verification_scope");
      requireCondition(Array.isArray(event.what.verification_scope) && event.what.verification_scope.length > 0, "ERR_INVALID_FIELD_TYPE", "verification_scope must be a non-empty array");
      requireCondition(event.what.verification_scope.every((x: any) => typeof x === "string" && x.length > 0), "ERR_INVALID_FIELD_TYPE", "verification scopes must be non-empty strings");
      requireCondition(new Set(event.what.verification_scope).size === event.what.verification_scope.length, "ERR_INVALID_FIELD_TYPE", "verification scopes must be unique");
    }
  }
}

function loadKeys(path?: string): Map<string, any> {
  const result = new Map<string, any>();
  if (!path) return result;
  const data = loadJsonUnique(path);
  requireCondition(data && typeof data === "object" && !Array.isArray(data), "ERR_INVALID_FIELD_TYPE", "key file must be an object");
  for (const [name, value] of Object.entries<any>(data)) {
    if (!value || typeof value !== "object") continue;
    const kid = typeof value.kid === "string" ? value.kid : name;
    result.set(kid, value);
  }
  return result;
}

function parseProtectedHeader(protectedB64: string): any {
  let header: any;
  try {
    const raw = UTF8_DECODER.decode(b64uDecode(protectedB64, "JWS protected header"));
    new JsonScanner(raw).parse();
    header = JSON.parse(raw);
    validateIJson(header, "$header");
  } catch (e: any) {
    if (e instanceof ValidationFault) throw e;
    throw new ValidationFault("ERR_SIGNATURE_CONTAINER_INVALID", `invalid JWS protected header: ${String(e?.message || e)}`, 1);
  }
  requireCondition(header && typeof header === "object" && !Array.isArray(header), "ERR_SIGNATURE_CONTAINER_INVALID", "protected header must be an object", 1);
  if ("crit" in header) {
    requireCondition(Array.isArray(header.crit) && header.crit.length > 0, "ERR_SIGNATURE_CONTAINER_INVALID", "JWS crit must be a non-empty array", 1);
    requireCondition(header.crit.every((x: any) => typeof x === "string" && x.length > 0), "ERR_SIGNATURE_CONTAINER_INVALID", "JWS crit entries must be non-empty strings", 1);
    requireCondition(new Set(header.crit).size === header.crit.length, "ERR_SIGNATURE_CONTAINER_INVALID", "JWS crit entries must be unique", 1);
    for (const name of header.crit) requireCondition(name in header, "ERR_SIGNATURE_CONTAINER_INVALID", `critical JOSE parameter ${name} is absent`, 1);
    throw new ValidationFault("ERR_SIGNATURE_CONTAINER_INVALID", `unsupported critical JOSE parameter(s): ${header.crit.join(", ")}`, 1);
  }
  if ("b64" in header && header.b64 !== true) throw new ValidationFault("ERR_SIGNATURE_CONTAINER_INVALID", "baseline requires ordinary base64url JWS payload encoding", 1);
  return header;
}

function verifyDetachedJws(event: any, payload: string, keys: Map<string, any>): { kid: string, jwk: any } {
  requireCondition(typeof event.sig === "string", "ERR_SIGNATURE_CONTAINER_INVALID", "sig must be a string", 1);
  const parts = event.sig.split(".");
  requireCondition(parts.length === 3 && parts[1] === "", "ERR_SIGNATURE_CONTAINER_INVALID", "detached compact JWS requires an empty payload segment", 1);
  const [protectedB64, , signatureB64] = parts;
  const header = parseProtectedHeader(protectedB64);
  requireCondition(typeof header.alg === "string", "ERR_SIGNATURE_CONTAINER_INVALID", "protected header requires alg", 1);
  if (header.alg !== "Ed25519") throw new ValidationFault("ERR_UNSUPPORTED_SIGNATURE_ALG", `unsupported baseline alg: ${header.alg}`, 1);
  requireCondition(typeof header.kid === "string" && header.kid.length > 0, "ERR_SIGNATURE_CONTAINER_INVALID", "protected header requires kid", 1);
  const jwk = keys.get(header.kid);
  if (!jwk) throw new ValidationFault("ERR_KEY_UNRESOLVED", `no public key for kid: ${header.kid}`, 1);
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") throw new ValidationFault("ERR_ALG_KEY_TYPE_MISMATCH", "Ed25519 requires an OKP/Ed25519 JWK", 1);
  if (jwk.alg !== undefined && jwk.alg !== "Ed25519") throw new ValidationFault("ERR_ALG_PROFILE_MISMATCH", "JWK alg does not match JWS alg", 1);
  if (jwk.use !== undefined && jwk.use !== "sig") throw new ValidationFault("ERR_PROHIBITED_SIGNATURE_ALG", "JWK use does not permit signatures", 1);
  if (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes("verify"))) throw new ValidationFault("ERR_PROHIBITED_SIGNATURE_ALG", "JWK key_ops does not permit verification", 1);
  requireCondition(typeof jwk.x === "string", "ERR_ALG_KEY_TYPE_MISMATCH", "Ed25519 JWK requires x", 1);
  const rawKey = b64uDecode(jwk.x, "JWK x");
  const signature = b64uDecode(signatureB64, "JWS signature");
  requireCondition(rawKey.length === 32, "ERR_ALG_KEY_TYPE_MISMATCH", "Ed25519 public key must be 32 bytes", 1);
  requireCondition(signature.length === 64, "ERR_SIGNATURE_INVALID", "Ed25519 signature must be 64 bytes", 1);
  try {
    const keyObject = crypto.createPublicKey({ key: jwk, format: "jwk" });
    const signingInput = Buffer.from(`${protectedB64}.${b64u(Buffer.from(payload, "utf8"))}`, "ascii");
    if (!crypto.verify(null, signingInput, keyObject, signature)) throw new Error("verification returned false");
  } catch {
    throw new ValidationFault("ERR_SIGNATURE_INVALID", "Ed25519 signature verification failed", 1);
  }
  return { kid: header.kid, jwk };
}

function actorBinding(event: any, kid: string, jwk: any, profile: string): void {
  if (profile === "none") return;
  if (jwk.revoked === true) throw new ValidationFault("ERR_KEY_REVOKED", `key is revoked under trust profile: ${kid}`, 2);
  if (profile === "kid-prefix") {
    if (kid.split("#", 1)[0] !== event.who) throw new ValidationFault("ERR_KEY_NOT_BOUND_TO_ACTOR", "kid controller is not the event actor", 2);
    return;
  }
  if (profile === "inline") {
    const actors: string[] = [];
    if (typeof jwk.actor === "string") actors.push(jwk.actor);
    if (Array.isArray(jwk.actors)) actors.push(...jwk.actors.filter((x: any) => typeof x === "string"));
    if (!actors.includes(event.who)) throw new ValidationFault("ERR_KEY_NOT_BOUND_TO_ACTOR", "key is not bound to event actor", 2);
    return;
  }
  throw new ValidationFault("ERR_TRUST_PROFILE_UNSUPPORTED", `unsupported local trust profile: ${profile}`, 2);
}

function processCriticalExtensions(event: any): void {
  const critical = event.ext_crit || [];
  const extensions = event.ext || {};
  for (const id of critical) {
    if (!(id in extensions)) throw new ValidationFault("ERR_EXTENSION_SCHEMA_INVALID", `critical extension ${id} is absent from ext`, 3);
    // No critical extension is accepted without a concrete handler.
    throw new ValidationFault("ERR_UNKNOWN_CRITICAL_EXTENSION", `unsupported critical extension: ${id}`, 3);
  }
}

function makeResult(valid: boolean, level: number, mode: string, profile: string, hash: string | null, scopes: string[], fault?: ValidationFault) {
  return {
    valid,
    level: Math.max(0, level),
    mode,
    profile,
    conformance_class: BASELINE_CLASS,
    scopes,
    event_hash: hash,
    warnings: [],
    errors: fault ? [fault.toJSON()] : [],
  };
}

function resolveParent(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  const slash = normalized.lastIndexOf("/");
  return slash < 0 ? "." : normalized.slice(0, slash) || "/";
}

interface ValidateOptions {
  mode: "archival" | "acceptance";
  trustProfile: "none" | "kid-prefix" | "inline";
  expectedAudience?: string;
  now?: number;
  maxAge: number;
  maxFutureSkew: number;
  replayCache?: string;
}

function validateEvent(event: any, keys: Map<string, any>, options: ValidateOptions) {
  const profile = options.trustProfile === "none" ? CORE_PROFILE : `${CORE_PROFILE}+local-${options.trustProfile}`;
  let level = -1;
  let hash: string | null = null;
  const scopes: string[] = [];
  try {
    validateShape(event);
    level = 0; scopes.push("syntax");
    const unsigned = { ...event }; delete unsigned.sig;
    const payload = canonicalize(unsigned);
    hash = eventHash(event);
    const verified = verifyDetachedJws(event, payload, keys);
    level = 1; scopes.push("cryptographic");
    actorBinding(event, verified.kid, verified.jwk, options.trustProfile);
    if (options.trustProfile !== "none") { level = 2; scopes.push("actor_binding"); }

    let cache: Set<string> | undefined;
    let replayKey: string | undefined;
    if (options.mode === "acceptance") {
      const now = options.now ?? Math.floor(Date.now() / 1000);
      if (event.when < now - options.maxAge) throw new ValidationFault("ERR_EVENT_EXPIRED", "event is older than the acceptance freshness window", 3);
      if (event.when > now + options.maxFutureSkew) throw new ValidationFault("ERR_TIMESTAMP_OUT_OF_WINDOW", "event timestamp is too far in the future", 3);
      if (!options.replayCache) throw new ValidationFault("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "acceptance mode requires a persistent replay cache", 3);
      const existing = fs.existsSync(options.replayCache) ? loadJsonUnique(options.replayCache) : [];
      requireCondition(Array.isArray(existing) && existing.every((x: any) => typeof x === "string"), "ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "replay cache must be a JSON string array", 3);
      cache = new Set(existing);
      replayKey = [event.who, event.aud || "", profile, event.nonce].join("\x1f");
      if (cache.has(replayKey)) throw new ValidationFault("ERR_NONCE_REPLAY", "nonce has already been accepted in this context", 3);
    }
    if (options.expectedAudience !== undefined && event.aud !== options.expectedAudience) throw new ValidationFault("ERR_DOMAIN_REQUIREMENT_UNSATISFIED", "aud does not match the expected validation context", 4);
    processCriticalExtensions(event);
    if (cache && replayKey && options.replayCache) {
      cache.add(replayKey);
      const temporary = `${options.replayCache}.${process.pid}.tmp`;
      fs.mkdirSync(resolveParent(options.replayCache), { recursive: true });
      fs.writeFileSync(temporary, JSON.stringify([...cache].sort(), null, 2) + "\n", "utf8");
      fs.renameSync(temporary, options.replayCache);
    }
    return makeResult(true, level, options.mode, profile, hash, scopes);
  } catch (e: any) {
    const fault = e instanceof ValidationFault ? e : new ValidationFault("ERR_INVALID_JSON", String(e?.message || e), 0);
    return makeResult(false, level, options.mode, profile, hash, scopes, fault);
  }
}

function parseArgs(argv: string[]) {
  const positional: string[] = [];
  const options: any = {
    mode: "archival",
    trustProfile: "none",
    maxAge: 300,
    maxFutureSkew: 60,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) { positional.push(arg); continue; }
    const value = argv[++i];
    if (value === undefined) throw new Error(`missing value for ${arg}`);
    if (arg === "--mode") options.mode = value;
    else if (arg === "--trust-profile") options.trustProfile = value;
    else if (arg === "--aud") options.expectedAudience = value;
    else if (arg === "--now") options.now = Number(value);
    else if (arg === "--max-age") options.maxAge = Number(value);
    else if (arg === "--max-future-skew") options.maxFutureSkew = Number(value);
    else if (arg === "--replay-cache") options.replayCache = value;
    else throw new Error(`unknown option ${arg}`);
  }
  if (!["archival", "acceptance"].includes(options.mode)) throw new Error("TypeScript seed supports archival or acceptance mode");
  if (!["none", "kid-prefix", "inline"].includes(options.trustProfile)) throw new Error("unsupported trust profile");
  for (const [name, value] of [["max-age", options.maxAge], ["max-future-skew", options.maxFutureSkew]]) {
    if (!Number.isInteger(value) || value < 0) throw new Error(`${name} must be a non-negative integer`);
  }
  if (options.now !== undefined && !Number.isInteger(options.now)) throw new Error("now must be an integer Unix timestamp");
  return { positional, options: options as ValidateOptions };
}

function main(): number {
  try {
    const { positional, options } = parseArgs(process.argv.slice(2));
    const file = positional[0];
    const keysPath = positional[1];
    if (!file) {
      console.error("usage: node dist/jep_validate.js <event.json> [keys.json] [--mode archival|acceptance] [--trust-profile none|kid-prefix|inline]");
      return 2;
    }
    const data = loadJsonUnique(file);
    const event = data && typeof data === "object" && "event" in data ? data.event : data;
    const output = validateEvent(event, loadKeys(keysPath), options);
    console.log(JSON.stringify(output, null, 2));
    return output.valid ? 0 : 1;
  } catch (e: any) {
    const fault = e instanceof ValidationFault ? e : new ValidationFault("ERR_INVALID_JSON", String(e?.message || e), 0);
    console.log(JSON.stringify(makeResult(false, -1, "archival", CORE_PROFILE, null, [], fault), null, 2));
    return 1;
  }
}

process.exit(main());

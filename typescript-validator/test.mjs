import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const validator = join(here, "dist", "jep_validate.js");
const vectors = join(root, "test-vectors", "interop");
const keys = join(vectors, "public-keys.json");

function run(file, keyFile = keys, extra = []) {
  const child = spawnSync(globalThis.process.execPath, [validator, join(vectors, file), keyFile, ...extra], {
    cwd: root,
    encoding: "utf8",
  });
  let output;
  try {
    output = JSON.parse(child.stdout);
  } catch (error) {
    throw new Error(`validator did not emit JSON for ${file}\nstdout=${child.stdout}\nstderr=${child.stderr}`, { cause: error });
  }
  return { process: child, output };
}

const validCases = [
  "control-J.json",
  "control-D.json",
  "control-T.json",
  "control-V-no-result.json",
  "JCS-number-small.json",
  "JCS-number-float-one.json",
  "JCS-UTF16-order.json",
  "JCS-html-chars.json",
];
for (const file of validCases) {
  const { process, output } = run(file);
  assert.equal(process.status, 0, `${file}: ${process.stderr}${process.stdout}`);
  assert.equal(output.valid, true, file);
  assert.equal(output.level, 1, file);
}

const invalidCases = [
  ["duplicate-member.json", keys, "ERR_DUPLICATE_MEMBER", 0],
  ["invalid-T-missing-target-scope.json", keys, "ERR_MISSING_REQUIRED_FIELD", 0],
  ["invalid-V-missing-scope.json", keys, "ERR_MISSING_REQUIRED_FIELD", 0],
  ["invalid-V-missing-what.json", keys, "ERR_MISSING_REQUIRED_FIELD", 0],
  ["invalid-nonce.json", keys, "ERR_INVALID_FIELD_TYPE", 0],
  ["invalid-when-string.json", keys, "ERR_INVALID_TIMESTAMP", 0],
  ["invalid-who-number.json", keys, "ERR_INVALID_FIELD_TYPE", 0],
  ["JOSE-unknown-critical.json", keys, "ERR_SIGNATURE_CONTAINER_INVALID", 0],
  ["JEP-unknown-critical-level.json", keys, "ERR_UNKNOWN_CRITICAL_EXTENSION", 1],
  ["JEP-known-critical-no-value.json", keys, "ERR_EXTENSION_SCHEMA_INVALID", 1],
  ["key-not-found-level.json", join(vectors, "key-not-found-level-keys.json"), "ERR_KEY_UNRESOLVED", 0],
  ["key-type-mismatch.json", join(vectors, "key-type-mismatch-keys.json"), "ERR_ALG_KEY_TYPE_MISMATCH", 0],
  ["invalid-signature-control.json", keys, "ERR_SIGNATURE_INVALID", 0],
  ["unknown-verb.json", keys, "ERR_UNKNOWN_VERB", 0],
];
for (const [file, keyFile, code, level] of invalidCases) {
  const { process, output } = run(file, keyFile);
  assert.equal(process.status, 1, file);
  assert.equal(output.valid, false, file);
  assert.equal(output.level, level, file);
  assert.equal(output.errors[0].code, code, file);
}

const temp = mkdtempSync(join(tmpdir(), "jep-ts-replay-"));
try {
  const cache = join(temp, "replay.json");
  const args = [
    "--mode", "acceptance",
    "--now", "1788397200",
    "--max-age", "300",
    "--max-future-skew", "60",
    "--replay-cache", cache,
  ];
  const first = run("control-J.json", keys, args);
  const second = run("control-J.json", keys, args);
  assert.equal(first.process.status, 0);
  assert.equal(first.output.valid, true);
  assert.equal(second.process.status, 1);
  assert.equal(second.output.errors[0].code, "ERR_NONCE_REPLAY");
} finally {
  rmSync(temp, { recursive: true, force: true });
}

console.log(`TypeScript conformance seed: ${validCases.length} valid and ${invalidCases.length} invalid vectors passed`);

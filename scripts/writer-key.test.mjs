// The server's own signing key, Ed25519 and hybrid: what it signs verifies as exactly that purpose.
// Run: node --no-warnings scripts/writer-key.test.mjs   (hybrid signing is slow: about two minutes)
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { isHybridKey } from "./hybrid-sig.mjs";
import { loadWriterKey } from "./writer-key.mjs";
import { writerVerify, writerVerifyFor } from "./log-core.mjs";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const tmp = fs.mkdtempSync(path.join(os.homedir(), ".zesuro-wkey-test-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));
const mk = (d) => { fs.mkdirSync(path.join(tmp, d), { recursive: true }); return path.join(tmp, d); };

// Ed25519
{
  const d = mk("ed"), k = loadWriterKey(d);
  ok(k.kind === "ed25519" && /^[A-Za-z0-9_-]{43}$/.test(k.publicKey) && fs.readFileSync(path.join(d, "anchor-key.pub"), "utf8").trim() === k.publicKey, "an Ed25519 key is made, with its public half published");
  ok((fs.statSync(path.join(d, "anchor-key.pem")).mode & 0o077) === 0, "the secret is private to its owner");
  ok(loadWriterKey(d).publicKey === k.publicKey, "the same key is loaded next time");
  const a = k.sign("anchor", "head text"), s = k.sign("snapshot", "head text");
  ok(writerVerify(k.publicKey, "head text", a) && writerVerifyFor(k.publicKey, "snapshot", "head text", s), "anchor and snapshot signatures verify");
  ok(!writerVerify(k.publicKey, "head text", s) && !writerVerifyFor(k.publicKey, "snapshot", "head text", a), "and neither verifies as the other");
  assert.throws(() => loadWriterKey(d, { wantHybrid: true }), /Refusing to replace/); n++;
  fs.writeFileSync(path.join(d, "anchor-key.json"), "{}");
  assert.throws(() => loadWriterKey(d), /Both anchor-key.pem and anchor-key.json/); n++;
}

// Hybrid, through the real anchor script
{
  const d = mk("hy");
  const db = new DatabaseSync(path.join(d, "whenisaid.db"));
  db.exec("CREATE TABLE entries (seq INTEGER PRIMARY KEY, entry_hash TEXT); CREATE TABLE comments (id INTEGER PRIMARY KEY, comment_hash TEXT); INSERT INTO entries VALUES (1, '" + "a".repeat(64) + "');");
  db.close();
  const r = spawnSync(process.execPath, ["--no-warnings", "scripts/anchor.mjs", "--hybrid"], { encoding: "utf8", env: { ...process.env, DATA_DIR: d } });
  ok(r.status === 0 && /Anchored 1 entries/.test(r.stdout), "anchor.mjs --hybrid makes a hybrid key and signs\n" + r.stdout + r.stderr);
  const pub = fs.readFileSync(path.join(d, "anchor-key.pub"), "utf8").trim();
  ok(isHybridKey(pub) && fs.existsSync(path.join(d, "anchor-key.json")) && !fs.existsSync(path.join(d, "anchor-key.pem")), "the key is hybrid and published as such");
  ok((fs.statSync(path.join(d, "anchor-key.json")).mode & 0o077) === 0, "the hybrid secret is private to its owner");
  const row = new DatabaseSync(path.join(d, "whenisaid.db"), { readOnly: true }).prepare("SELECT head, sig FROM anchors ORDER BY id DESC LIMIT 1").get();
  ok(writerVerify(pub, row.head, row.sig), "the stored anchor verifies against the hybrid key");
  ok(!writerVerify(pub, row.head + " ", row.sig), "and not against altered text");
  const k = loadWriterKey(d);
  ok(k.kind === "hybrid" && k.publicKey === pub, "the same hybrid key is loaded next time");
  const s = k.sign("snapshot", "manifest");
  ok(writerVerifyFor(pub, "snapshot", "manifest", s) && !writerVerify(pub, "manifest", s), "a hybrid snapshot signature verifies as a snapshot and not as an anchor");
}

console.log(`All ${n} writer-key checks passed`);

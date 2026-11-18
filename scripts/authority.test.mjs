// Tests for the root key and delegations (scripts/root.mjs + scripts/log-core.mjs).
// Run: node --no-warnings scripts/authority.test.mjs   (signing with SLH-DSA is slow; this makes only a few signatures)
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import * as hybrid from "./hybrid-sig.mjs";
import { ZERO, authorityProblem, delegationsOf, rightfulWriter } from "./log-core.mjs";
import { generateRecovery } from "./snapshot-core.mjs";
import { currentRecovery } from "./log-core.mjs";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const eq = (a, b, m) => { assert.equal(a, b, m); n++; };

const tmp = fs.mkdtempSync(path.join(os.homedir(), ".zesuro-auth-test-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));
const run = (...args) => spawnSync(process.execPath, ["--no-warnings", path.resolve("scripts/root.mjs"), ...args], { encoding: "utf8" });

// A mirror folder to delegate from: two entries and one comment, so the starting point is non-trivial
const mirror = path.join(tmp, "mirror"); fs.mkdirSync(mirror);
const H = (c) => c.repeat(64);
fs.writeFileSync(path.join(mirror, "entries.jsonl"), [{ entryHash: H("a") }, { entryHash: H("b") }].map((x) => JSON.stringify(x)).join("\n") + "\n");
fs.writeFileSync(path.join(mirror, "comments.jsonl"), JSON.stringify({ commentHash: H("c") }) + "\n");

// init: hybrid root, recovery key, refusal to overwrite
const dir = path.join(tmp, "root"), authFile = path.join(tmp, "authority.json");
let r = run("init", "--dir", dir);
eq(r.status, 0, r.stderr);
const rootSecret = fs.readFileSync(path.join(dir, "root-key.json"), "utf8");
const root = hybrid.publicKeyOf(rootSecret);
ok(hybrid.isHybridKey(root) && r.stdout.includes(root), "init makes a hybrid root key and prints its public half");
eq(fs.statSync(path.join(dir, "root-key.json")).mode & 0o077, 0, "root key file is private to its owner");
ok(!r.stdout.includes(JSON.parse(rootSecret).slh), "the secret is never printed");
ok(run("init", "--dir", dir).status !== 0, "init refuses to replace an existing root key");

// First delegation to a legacy (Ed25519-only) writer, from the mirror's copy
const w1 = generateKeyPairSync("ed25519");
const w1pub = w1.publicKey.export({ format: "jwk" }).x;
r = run("delegate", "--writer", w1pub, "--from", mirror, "--dir", dir, "--authority", authFile);
eq(r.status, 0, r.stderr);
let auth = JSON.parse(fs.readFileSync(authFile, "utf8"));
eq(auth.root, root, "authority file names the hybrid root");
eq(authorityProblem(auth, root), null, "a fresh authority file is valid");
const d1 = delegationsOf(auth)[0];
eq(d1.from.entries.count, 2, "delegation starts at the mirror's entry count");
eq(d1.from.entries.tip, H("b"), "and its tip");
eq(d1.from.comments.tip, H("c"), "and the comment tip");

// Second delegation to a hybrid writer
const w2 = hybrid.generate();
fs.appendFileSync(path.join(mirror, "entries.jsonl"), JSON.stringify({ entryHash: H("d") }) + "\n");
r = run("delegate", "--writer", w2.publicKey, "--from", mirror, "--dir", dir, "--authority", authFile);
eq(r.status, 0, r.stderr);
auth = JSON.parse(fs.readFileSync(authFile, "utf8"));
eq(authorityProblem(auth, root), null, "two delegations, the second to a hybrid writer, are valid");
const ds = delegationsOf(auth);

// Forgery attempts against the authority file
const clone = () => JSON.parse(JSON.stringify(auth));
{
  const other = hybrid.generate();
  ok(authorityProblem(auth, other.publicKey), "a different root key does not accept this file");
  ok(authorityProblem(auth, w1pub), "a bare Ed25519 key is not accepted as a root");
  const f = clone(); f.delegations[0].sig = f.delegations[0].sig.split(".").map((p, i) => (i === 1 ? "A" + p.slice(1) : p)).join(".");
  ok(authorityProblem(f, root), "damaged Ed25519 half is caught");
  const g = clone(); g.delegations[0].sig = g.delegations[0].sig.split(".").map((p, i) => (i === 2 ? "A" + p.slice(1) : p)).join(".");
  ok(authorityProblem(g, root), "damaged SLH-DSA half is caught");
  const h = clone(); h.delegations[1].head = h.delegations[1].head.replace(/"serial":2/, '"serial":3');
  ok(authorityProblem(h, root), "editing a signed delegation is caught");
  // The recovery key snapshots are encrypted to is covered by the root's signature
  const attackerRecovery = generateRecovery().publicKey;
  const swapRec = clone(); swapRec.recovery = attackerRecovery;
  ok(authorityProblem(swapRec, root), "swapping the recovery key in the file is caught");
  const swapHead = clone(); { const hd = JSON.parse(swapHead.delegations[1].head); hd.recovery = attackerRecovery; swapHead.delegations[1].head = JSON.stringify(hd); swapHead.recovery = attackerRecovery; }
  ok(authorityProblem(swapHead, root), "changing it inside a signed delegation breaks the root's signature");
  ok(currentRecovery(auth) === auth.recovery && auth.recovery.startsWith("zk1."), "the recovery key in force is the hybrid one the root signed");
  const swap = clone(); swap.delegations.reverse();
  ok(authorityProblem(swap, root), "reordering delegations is caught");
  const drop = clone(); drop.delegations.shift();
  ok(authorityProblem(drop, root), "dropping the first delegation is caught");
  // A forger who can only break Ed25519 (as a quantum computer could) cannot add a delegation:
  const evilHead = JSON.stringify({ v: 1, type: "delegation", serial: 3, writer: w1pub, from: ds[1].from, at: Date.now() });
  const edHalf = edSign(null, Buffer.from("x"), w1.privateKey).toString("base64url"); // any valid-looking Ed signature
  const forged = clone(); forged.delegations.push({ head: evilHead, sig: `zs1.${edHalf}.${"A".repeat(10464)}` });
  ok(authorityProblem(forged, root), "a delegation without a valid SLH-DSA half is rejected");
  // A delegation signed for another purpose cannot be passed off as a delegation
  const wrongPurpose = hybrid.sign(rootSecret, "anchor", evilHead);
  const forged2 = clone(); forged2.delegations.push({ head: evilHead, sig: wrongPurpose });
  ok(authorityProblem(forged2, root), "a root signature made for another purpose is not a delegation");
}

// Who may write, where
const head = (ec, cc) => JSON.stringify({ v: 1, at: 1, entries: { count: ec, tip: H("e") }, comments: { count: cc, tip: H("f") } });
const anchorSigByW2 = (text) => hybrid.sign(w2.secret, "anchor", text);
const legacySig = (text) => edSign(null, Buffer.from(text), w1.privateKey).toString("base64url");
{
  const t1 = head(2, 1), tAt = head(3, 1), t2 = head(4, 1); // the second delegation starts at entry 3
  eq(rightfulWriter(ds, JSON.parse(t1), t1, legacySig(t1)), w1pub, "the first writer may sign tips up to the handover point");
  eq(rightfulWriter(ds, JSON.parse(t1), t1, "AAAA"), null, "a bad signature is refused");
  eq(rightfulWriter(ds, JSON.parse(tAt), tAt, legacySig(tAt)), w1pub, "at exactly the handover point the old writer's tip is still accepted (it is the shared state)");
  const beyond = head(5, 1);
  eq(rightfulWriter(ds, JSON.parse(beyond), beyond, legacySig(beyond)), null, "the old writer may not sign beyond its handover");
  const s2 = anchorSigByW2(t2);
  eq(rightfulWriter(ds, JSON.parse(t2), t2, s2), w2.publicKey, "the new hybrid writer may sign from the handover on");
  eq(rightfulWriter(ds, JSON.parse(t2), t2, legacySig(t2)), null, "the old writer's signature does not count after handover");
  eq(rightfulWriter(ds, JSON.parse(t2), t2, hybrid.sign(w2.secret, "delegation", t2)), null, "a writer key signing for another purpose is not an anchor");
}

console.log(`All ${n} authority checks passed`);

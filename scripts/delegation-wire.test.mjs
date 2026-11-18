// End-to-end: mirror.mjs and verify-log.mjs against a fake site, with and without the right root key.
// Run: node --no-warnings scripts/delegation-wire.test.mjs   (two hybrid signatures: takes a minute or two)
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import * as hybrid from "./hybrid-sig.mjs";
import { ZERO } from "./log-core.mjs";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const node = (...a) => spawnSync(process.execPath, ["--no-warnings", ...a], { encoding: "utf8" });
const tmp = fs.mkdtempSync(path.join(os.homedir(), ".zesuro-wire-test-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));

// Two possible writers, one root. Delegation chain A names the real writer; chain B (a rival history) names someone else.
const real = generateKeyPairSync("ed25519"), rogue = generateKeyPairSync("ed25519"), other = generateKeyPairSync("ed25519");
const pubOf = (k) => k.publicKey.export({ format: "jwk" }).x;
const rootDir = path.join(tmp, "root");
let r = node("scripts/root.mjs", "init", "--dir", rootDir); assert.equal(r.status, 0, r.stderr);
const root = hybrid.publicKeyOf(fs.readFileSync(path.join(rootDir, "root-key.json"), "utf8"));
const authA = path.join(tmp, "authA.json"), authB = path.join(tmp, "authB.json");
r = node("scripts/root.mjs", "delegate", "--writer", pubOf(real), "--from", "genesis", "--dir", rootDir, "--authority", authA); assert.equal(r.status, 0, r.stderr);
r = node("scripts/root.mjs", "delegate", "--writer", pubOf(other), "--from", "genesis", "--dir", rootDir, "--authority", authB); assert.equal(r.status, 0, r.stderr);
const A = JSON.parse(fs.readFileSync(authA, "utf8")), B = JSON.parse(fs.readFileSync(authB, "utf8"));

// An empty record with signed anchors over its (empty) tips
const headText = JSON.stringify({ v: 1, at: 1700000000000, entries: { count: 0, tip: ZERO }, comments: { count: 0, tip: ZERO } });
const sigBy = (k) => edSign(null, Buffer.from(headText), k.privateKey).toString("base64url");

const site = { authority: A, signer: real, publish: real };
const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  const json = (o, code = 200) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  if (u.pathname === "/api/log") return json({ entries: [] });
  if (u.pathname === "/api/log/comments") return json({ comments: [] });
  if (u.pathname === "/api/chain") return json({ ok: true, count: 0, tip: ZERO, comments: { ok: true, count: 0, tip: ZERO } });
  if (u.pathname === "/api/authority") return site.authority ? json(site.authority) : json({ error: "none" }, 404);
  if (u.pathname === "/api/anchors") return json({ publicKey: pubOf(site.publish), anchors: [{ id: 1, at: 1700000000000, head: JSON.parse(headText), sig: sigBy(site.signer), witnesses: [] }] });
  if (u.pathname === "/api/anchors/1/head") { res.writeHead(200); return res.end(headText); }
  json({ error: "nope" }, 404);
});
await new Promise((res) => server.listen(0, "127.0.0.1", res));
const url = `http://127.0.0.1:${server.address().port}`;
const mirror = (dir, ...extra) => new Promise((resolve) => {
  const p = spawn(process.execPath, ["--no-warnings", "scripts/mirror.mjs", url, "--dir", path.join(tmp, dir), ...extra], { encoding: "utf8" });
  let out = ""; p.stdout.on("data", (d) => (out += d)); p.stderr.on("data", (d) => (out += d));
  p.on("close", (code) => resolve({ code, out }));
});
// Async on purpose: the fake site lives in this process, so blocking here would stop it answering.
const verifier = (...extra) => new Promise((resolve) => {
  const p = spawn(process.execPath, ["--no-warnings", "scripts/verify-log.mjs", url, ...extra]);
  let stdout = "", stderr = ""; p.stdout.on("data", (d) => (stdout += d)); p.stderr.on("data", (d) => (stderr += d));
  p.on("close", (status) => resolve({ status, stdout, stderr }));
});

// 1. Correct root, correct signer
let m = await mirror("m1", "--root", root);
ok(m.code === 0 && /Pinned the root key/.test(m.out) && /Authority updated: 1 delegation/.test(m.out), "mirror with the right root accepts the delegated writer\n" + m.out);
ok(fs.existsSync(path.join(tmp, "m1", "authority.json")), "mirror keeps the authority file");
let v = await verifier("--root", root);
ok(v.status === 0 && /checked against the root key/.test(v.stdout), "verifier with the right root passes\n" + v.stdout + v.stderr);
v = await verifier();
ok(v.status === 0 && /No --root given/.test(v.stdout), "verifier without a root passes but says what it did not check\n" + v.stdout + v.stderr);

// 2. A root key the operator did not make
const wrongRoot = hybrid.generate().publicKey;
m = await mirror("m2", "--root", wrongRoot);
ok(m.code === 2 && /bad-authority/.test(m.out), "mirror pinned to another root rejects this authority file\n" + m.out);
v = await verifier("--root", wrongRoot);
ok(v.status === 1 && /FAIL\s+authority/.test(v.stdout), "verifier with another root fails\n" + v.stdout + v.stderr);

// 3. A server the root never authorised signs the anchors (a seized or impostor server)
site.signer = rogue; site.publish = rogue;
m = await mirror("m3", "--root", root);
ok(m.code === 2 && /not-delegated/.test(m.out), "mirror alarms when the site signs with an undelegated key\n" + m.out);
v = await verifier("--root", root);
ok(v.status === 1 && /latest delegation names/.test(v.stdout), "verifier fails for the undelegated key\n" + v.stdout + v.stderr);
// Even if it claims the real writer's key, its signatures do not verify as that writer
site.publish = real;
m = await mirror("m3b", "--root", root);
ok(m.code === 2 && /bad-anchor/.test(m.out), "claiming the real key without its signature is caught\n" + m.out);
site.signer = real;

// 4. No authority published at all
site.authority = null;
m = await mirror("m4", "--root", root);
ok(m.code === 2 && /no-authority/.test(m.out), "mirror will not accept anchors when no authority is published\n" + m.out);
v = await verifier("--root", root);
ok(v.status === 1, "verifier fails when no authority is published\n" + v.stdout + v.stderr);

// 5. The site later serves a different history of delegations: m1 already holds chain A
site.authority = B; site.signer = other; site.publish = other;
m = await mirror("m1", "--root", root);
ok(m.code === 2 && /authority-rewritten/.test(m.out), "mirror refuses an authority file that does not continue the one it holds\n" + m.out);
ok(JSON.parse(fs.readFileSync(path.join(tmp, "m1", "authority.json"), "utf8")).delegations[0].head === A.delegations[0].head, "and keeps what it held");

// 6. The root pin cannot be changed afterwards
m = await mirror("m1", "--root", wrongRoot);
ok(m.code === 64 && /pinned to root key/.test(m.out), "a mirror will not switch to a different root key\n" + m.out);

server.close();
console.log(`All ${n} wiring checks passed`);

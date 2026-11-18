// mirror.mjs --standby against a fake site: it keeps a genuine snapshot and refuses forged ones.
// Run: node --no-warnings scripts/standby.test.mjs   (one hybrid signature: about a minute)
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createHash, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import * as hybrid from "./hybrid-sig.mjs";
import { ZERO, writerBytes } from "./log-core.mjs";
import { generateRecovery, sealSnapshot } from "./snapshot-core.mjs";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const sha = (b) => createHash("sha256").update(b).digest("hex");
const tmp = fs.mkdtempSync(path.join(os.homedir(), ".zesuro-standby-test-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));

const rootDir = path.join(tmp, "root"), authFile = path.join(tmp, "authority.json");
const writer = generateKeyPairSync("ed25519"), rogue = generateKeyPairSync("ed25519");
const wPub = writer.publicKey.export({ format: "jwk" }).x;
let r = spawnSync(process.execPath, ["--no-warnings", "scripts/root.mjs", "init", "--dir", rootDir], { encoding: "utf8" }); assert.equal(r.status, 0, r.stderr);
r = spawnSync(process.execPath, ["--no-warnings", "scripts/root.mjs", "delegate", "--writer", wPub, "--from", "genesis", "--dir", rootDir, "--authority", authFile], { encoding: "utf8" }); assert.equal(r.status, 0, r.stderr);
const auth = JSON.parse(fs.readFileSync(authFile, "utf8"));
const root = hybrid.publicKeyOf(fs.readFileSync(path.join(rootDir, "root-key.json"), "utf8"));

const meta = { at: Date.now(), entries: { count: 0, tip: ZERO }, comments: { count: 0, tip: ZERO } };
const file = sealSnapshot(Buffer.from("pretend database ".repeat(1000)), auth.recovery, meta);
const name = `snapshot-${meta.at}.zsnap`;
const mkManifest = (bytes, key) => {
  const text = JSON.stringify({ v: 1, ...meta, name, size: bytes.length, sha256: sha(bytes) });
  return { manifest: text, sig: edSign(null, writerBytes("snapshot", text), key.privateKey).toString("base64url") };
};

const site = { latest: mkManifest(file, writer), file, accepted: new Set(), served: 0, authAttempts: [] };
const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  const json = (o, c = 200) => { res.writeHead(c, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  if (u.pathname === "/api/log") return json({ entries: [] });
  if (u.pathname === "/api/log/comments") return json({ comments: [] });
  if (u.pathname === "/api/chain") return json({ ok: true, count: 0, tip: ZERO, comments: { ok: true, count: 0, tip: ZERO } });
  if (u.pathname === "/api/authority") return json(auth);
  if (u.pathname === "/api/anchors") return json({ publicKey: wPub, anchors: [] });
  if (u.pathname === "/api/snapshot/latest") return json(site.latest);
  if (u.pathname === `/api/snapshot/${name}`) {
    // The same check the real route makes: an accepted key, a fresh time, a signature over this request
    const key = req.headers["x-zesuro-key"], at = Number(req.headers["x-zesuro-at"]), sig = req.headers["x-zesuro-sig"];
    let good = false;
    try { good = site.accepted.has(key) && Math.abs(Date.now() - at) < 300000 && edVerify(null, Buffer.from(`zesuro:snapshot-get:v1:${name}:${at}`), createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key }, format: "jwk" }), Buffer.from(sig, "base64url")); } catch { good = false; }
    site.authAttempts.push(good);
    if (!good) { res.writeHead(401); return res.end("{}"); }
    site.served++;
    res.writeHead(200, { "content-type": "application/octet-stream" }); return res.end(site.file);
  }
  json({ error: "nope" }, 404);
});
await new Promise((res) => server.listen(0, "127.0.0.1", res));
const url = `http://127.0.0.1:${server.address().port}`;
const mirror = (dir, ...extra) => new Promise((resolve) => {
  const p = spawn(process.execPath, ["--no-warnings", "scripts/mirror.mjs", url, "--dir", path.join(tmp, dir), "--root", root, "--standby", ...extra]);
  let out = ""; p.stdout.on("data", (d) => (out += d)); p.stderr.on("data", (d) => (out += d));
  p.on("close", (code) => resolve({ code, out }));
});
const keyOf = (dir) => hybrid && fs.existsSync(path.join(tmp, dir, "witness-key.pem")) ? createPublicKey({ key: fs.readFileSync(path.join(tmp, dir, "witness-key.pem")) }).export({ format: "jwk" }).x : null;

// 1. Not accepted yet: nothing is downloaded, and it says why (the first run also makes the key)
let m = await mirror("s1");
ok(m.code === 0 && /not accepted this mirror's key as a standby/.test(m.out) && !fs.existsSync(path.join(tmp, "s1", "snapshots", name)), "an unaccepted standby gets nothing, without alarm\n" + m.out);
const standbyKey = keyOf("s1");
ok(/^[A-Za-z0-9_-]{43}$/.test(standbyKey ?? ""), "the standby has a key to give the operator");

// 2. Accepted: it downloads, checks and keeps the snapshot
site.accepted.add(standbyKey);
m = await mirror("s1");
ok(m.code === 0 && /snapshot kept/.test(m.out) && fs.readFileSync(path.join(tmp, "s1", "snapshots", name)).equals(file), "an accepted standby keeps the snapshot\n" + m.out);
ok(fs.existsSync(path.join(tmp, "s1", "snapshots", "latest.json")), "and its signed manifest");
const served = site.served;
m = await mirror("s1");
ok(site.served === served, "a snapshot already held is not downloaded again");

// 3. The file is swapped for another under the same name: the manifest's hash catches it
site.file = Buffer.concat([file.subarray(0, file.length - 1), Buffer.from([file[file.length - 1] ^ 1])]);
m = await mirror("s2"); // a fresh mirror with its own key
site.accepted.add(keyOf("s2"));
m = await mirror("s2");
ok(m.code === 2 && /bad-snapshot/.test(m.out) && !fs.existsSync(path.join(tmp, "s2", "snapshots", name)), "a swapped file is refused and not kept\n" + m.out);
site.file = file;

// 4. A manifest signed by a server the root never delegated to
site.latest = mkManifest(file, rogue);
m = await mirror("s3"); site.accepted.add(keyOf("s3")); m = await mirror("s3");
ok(m.code === 2 && /bad-snapshot/.test(m.out) && !fs.existsSync(path.join(tmp, "s3", "snapshots", name)), "a manifest from an undelegated signer is refused\n" + m.out);

server.close();
console.log(`All ${n} standby checks passed`);

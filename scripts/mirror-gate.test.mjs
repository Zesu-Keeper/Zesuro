// A mirror may serve the record only if the root-signed list names its address.
// Run: node --no-warnings scripts/mirror-gate.test.mjs   (one slow hybrid signature)
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import * as hybrid from "./hybrid-sig.mjs";
let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };
const tmp = fs.mkdtempSync(path.join(os.homedir(), ".zesuro-gate-test-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));
const k = hybrid.generate(), root = hybrid.publicKeyOf(k.secret);
const manifest = JSON.stringify({ v: 1, serial: 5, at: Date.now(), mirrors: [{ url: "https://good.example", name: "Good", at: 1 }], malicious: [{ url: "https://evil.example", reason: "copies the site", at: 1 }] });
const list = JSON.stringify({ manifest, sig: hybrid.sign(k.secret, "sites", manifest) });
let serveList = true;
const origin = http.createServer((req, res) => {
  if (req.url === "/api/sites" && serveList) { res.setHeader("content-type", "application/json"); return res.end(list); }
  res.statusCode = 404; res.end("{}");
});
await new Promise((r) => origin.listen(0, "127.0.0.1", r));
const src = `http://127.0.0.1:${origin.address().port}`;
const run = (url, extra = []) => new Promise((resolve) => {
  const dir = path.join(tmp, "m" + Math.random().toString(36).slice(2));
  const p = spawn(process.execPath, ["--no-warnings", path.resolve("scripts/mirror.mjs"), src, "--dir", dir, "--serve", String(41000 + Math.floor(Math.random() * 2000)), "--root", root, "--public-url", url, ...extra], { stdio: ["ignore", "pipe", "pipe"] });
  let out = ""; p.stdout.on("data", (d) => { out += d; if (/Serving this copy/.test(out)) p.kill(); }); p.stderr.on("data", (d) => (out += d));
  p.on("exit", (code) => resolve({ code, out, dir }));
  setTimeout(() => p.kill(), 20000);
});
let r = await run("https://good.example"); ok(/Serving this copy/.test(r.out), "a listed mirror may serve: code " + r.code + " " + r.out);
ok(fs.readFileSync(path.join(r.dir, "sites-serial"), "utf8") === "5", "the list's serial is remembered");
r = await run("https://other.example"); ok(r.code === 3 && /not on the root's list/.test(r.out), "an unlisted address may not serve: " + r.out.slice(0, 200));
r = await run("https://evil.example"); ok(r.code === 3 && /impostor/.test(r.out), "a listed impostor may not serve");
r = await new Promise((resolve) => { const p = spawn(process.execPath, ["--no-warnings", path.resolve("scripts/mirror.mjs"), src, "--dir", path.join(tmp, "x"), "--serve", String(41000 + Math.floor(Math.random() * 2000))], { stdio: ["ignore", "pipe", "pipe"] }); let o = ""; p.stderr.on("data", (d) => (o += d)); p.on("exit", (c) => resolve({ code: c, out: o })); });
ok(r.code === 64, "serving without --root and --public-url is refused");
const other = hybrid.generate();
r = await run("https://good.example", []); // same list, but pin a different root below
r = await new Promise((resolve) => { const p = spawn(process.execPath, ["--no-warnings", path.resolve("scripts/mirror.mjs"), src, "--dir", path.join(tmp, "y"), "--serve", String(41000 + Math.floor(Math.random() * 2000)), "--root", hybrid.publicKeyOf(other.secret), "--public-url", "https://good.example"], { stdio: ["ignore", "pipe", "pipe"] }); let o = ""; p.stderr.on("data", (d) => (o += d)); p.on("exit", (c) => resolve({ code: c, out: o })); });
ok(r.code === 3 && /not acceptable/.test(r.out), "a list signed by another root is refused");
serveList = false; r = await run("https://good.example"); ok(r.code === 3, "no list at the source means no serving");
origin.close(); console.log(`All ${n} mirror-gate checks passed`);

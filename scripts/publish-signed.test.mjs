// Tests the one-command signing helper using a folder in place of a server.
// Run: node --no-warnings scripts/publish-signed.test.mjs   (two hybrid signatures, slow)
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as hybrid from "./hybrid-sig.mjs";
import { sitesProblem } from "./sites-core.mjs";
let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };
const tmp = fs.mkdtempSync(path.join(os.homedir(), ".zesuro-pub-test-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));
const keyDir = path.join(tmp, "zesuro-root"), server = path.join(tmp, "server"); fs.mkdirSync(keyDir); fs.mkdirSync(server);
const k = hybrid.generate(); fs.writeFileSync(path.join(keyDir, "root-key.json"), k.secret);
const root = hybrid.publicKeyOf(k.secret);
fs.writeFileSync(path.join(server, "release-draft.json"), JSON.stringify({ v: 1, commit: "abc123abc123", at: 1, files: { "/_next/static/a.js": "a".repeat(64) } }));
fs.writeFileSync(path.join(tmp, "sites-draft.json"), JSON.stringify({ v: 1, serial: 0, at: 0, mirrors: [{ url: "https://m.example", name: "M", at: 1 }], malicious: [] }));
const run = (...a) => spawnSync(process.execPath, ["--no-warnings", path.resolve("scripts/publish-signed.mjs"), ...a], { encoding: "utf8", cwd: tmp });
let r = run(server, "--dir", keyDir);
ok(r.status === 0, r.stderr + r.stdout);
const rel = JSON.parse(fs.readFileSync(path.join(server, "release.json"), "utf8"));
ok(hybrid.verify(root, "release", rel.manifest, rel.sig), "the uploaded release verifies against the root key");
ok(JSON.parse(rel.manifest).files["/_next/static/a.js"] === "a".repeat(64), "it signs exactly the staged hashes");
const sites = JSON.parse(fs.readFileSync(path.join(server, "sites.json"), "utf8"));
ok(sitesProblem(sites, root) === null && JSON.parse(sites.manifest).serial === 1, "the mirrors list is signed too, serial 1");
r = run(server, "--dir", keyDir); ok(r.status === 0, r.stderr);
ok(JSON.parse(JSON.parse(fs.readFileSync(path.join(server, "sites.json"), "utf8")).manifest).serial === 2, "a second run raises the serial");
r = run(server, "--dir", path.join(tmp, "nokey")); ok(r.status === 1 && /No root key/.test(r.stderr), "no key, no signing");
console.log(`All ${n} publish-signed checks passed`);

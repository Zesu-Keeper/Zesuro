// Tests for the signed mirrors / impostors directory (scripts/sites.mjs + scripts/sites-core.mjs).
// Run: node --no-warnings scripts/sites.test.mjs   (signing with SLH-DSA is slow; this makes a few signatures)
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as hybrid from "./hybrid-sig.mjs";
import { classify, manifestProblem, normUrl, sitesProblem } from "./sites-core.mjs";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const eq = (a, b, m) => { assert.equal(a, b, m); n++; };
const tmp = fs.mkdtempSync(path.join(os.homedir(), ".zesuro-sites-test-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));
const sites = (...a) => spawnSync(process.execPath, ["--no-warnings", path.resolve("scripts/sites.mjs"), ...a, "--draft", path.join(tmp, "d.json")], { encoding: "utf8" });
const dir = path.join(tmp, "root"); fs.mkdirSync(dir);
const rootSecret = hybrid.generate().secret; fs.writeFileSync(path.join(dir, "root-key.json"), rootSecret);
const root = hybrid.publicKeyOf(rootSecret), other = hybrid.generate();
const out = path.join(tmp, "sites.json");
const FAKEKEY = hybrid.generate().publicKey;

// addresses
eq(normUrl("https://Mirror.Example/"), "https://mirror.example", "origin is lowercased");
for (const bad of ["http://a.example", "https://u:p@a.example", "https://a.example/x", "https://a.example/?q=1", "javascript:alert(1)", "nonsense"]) eq(normUrl(bad), null, `refused: ${bad}`);

// build a list with the CLI
let r = sites("add-mirror", "--url", "https://mirror.example", "--name", "Example mirror", "--note", "run by a friend");
eq(r.status, 0, r.stderr);
r = sites("add-malicious", "--url", "https://zesur0.com", "--key", FAKEKEY, "--reason", "copies the look of the site and asks for keys");
eq(r.status, 0, r.stderr);
eq(sites("add-malicious", "--reason", "x").status, 1, "needs a url or key");
eq(sites("add-mirror", "--url", "http://plain.example", "--name", "x").status, 1, "http refused");
eq(sites("add-malicious", "--url", "https://zesur0.com").status, 1, "reason required");
r = sites("sign", "--dir", dir, "--out", out); eq(r.status, 0, r.stderr);

const file = JSON.parse(fs.readFileSync(out, "utf8"));
eq(sitesProblem(file, root), null, "a signed list verifies");
eq(JSON.parse(file.manifest).serial, 1, "first serial is 1");
ok(sitesProblem(file, other.publicKey) !== null, "another root key does not verify it");
ok(sitesProblem({ ...file, manifest: file.manifest.replace("Example mirror", "Evil mirror") }, root) !== null, "an edited list fails");
ok(sitesProblem({ ...file, sig: file.sig.slice(0, -2) + "AA" }, root) !== null, "a damaged signature fails");
// purpose separation: a release signature must not pass as a sites list
const asRelease = { manifest: file.manifest, sig: hybrid.sign(rootSecret, "release", file.manifest) };
ok(sitesProblem(asRelease, root) !== null, "a signature for another purpose is refused");
ok(sitesProblem(file, root, 2) !== null, "an older serial than already seen is refused");
eq(sitesProblem(file, root, 1), null, "the same serial is fine");

// classification
const m = JSON.parse(file.manifest);
eq(classify(m, { url: "https://MIRROR.example/" }), "mirror");
eq(classify(m, { url: "https://zesur0.com" }), "malicious");
eq(classify(m, { key: FAKEKEY }), "malicious", "a bad key is caught even from a new address");
eq(classify(m, { url: "https://other.example" }), "unknown");

// contradiction: same address in both lists is refused by the checker and by the CLI
const clash = { ...m, malicious: [...m.malicious, { url: "https://mirror.example", reason: "r", at: 1 }] };
ok(manifestProblem(clash) !== null, "a site can't be both mirror and malicious");
ok(manifestProblem({ ...m, mirrors: [...m.mirrors, ...m.mirrors] }) !== null, "duplicates refused");
ok(manifestProblem({ ...m, mirrors: [{ url: "https://a.example", name: "bad\u0007name", at: 1 }] }) !== null, "control characters refused");
ok(manifestProblem({ ...m, malicious: [{ reason: "no target", at: 1 }] }) !== null, "a malicious entry needs a target");

// moving a site to malicious takes it off the mirror list; the serial goes up
r = sites("add-malicious", "--url", "https://mirror.example", "--reason", "turned out to alter entries"); eq(r.status, 0, r.stderr);
r = sites("sign", "--dir", dir, "--out", out); eq(r.status, 0, r.stderr);
const f2 = JSON.parse(fs.readFileSync(out, "utf8")), m2 = JSON.parse(f2.manifest);
eq(m2.serial, 2, "serial rises");
eq(m2.mirrors.length, 0, "no longer a mirror");
eq(classify(m2, { url: "https://mirror.example" }), "malicious");
eq(sitesProblem(f2, root, 2), null);
eq(sites("verify", "--file", out, "--root", root).status, 0, "verify command accepts");
eq(sites("verify", "--file", out, "--root", other.publicKey).status, 1, "verify command rejects another root");
eq(sites("remove", "--url", "https://zesur0.com").status, 0, "remove works");
eq(sites("remove", "--url", "https://nothing.example").status, 1, "removing nothing is reported");
console.log(`All ${n} sites checks passed`);

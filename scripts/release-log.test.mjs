// The release log: server side (lib/release-log.ts) and the outside checks (scripts/release-log-core.mjs).
// Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/release-log.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
process.chdir(fs.mkdtempSync(path.join(os.tmpdir(), "rlog-")));
fs.mkdirSync("data");
const L = await import(path.join(root, "src/lib/release-log.ts"));
const C = await import(path.join(root, "scripts/release-log-core.mjs"));
let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };

ok(L.readReleaseLog(0, 10).count === 0, "no release, empty log");
fs.writeFileSync("data/release.json", JSON.stringify({ manifest: '{"v":1,"commit":"aaa","files":{}}', sig: "x" }));
L.syncReleaseLog(1000);
L.syncReleaseLog(2000);
let log = L.readReleaseLog(0, 10);
ok(log.count === 1 && log.releases[0].at === 1000, "a release is logged once");
fs.writeFileSync("data/release.json", JSON.stringify({ manifest: '{"v":1,"commit":"bbb","files":{}}', sig: "y" }));
L.syncReleaseLog(3000);
log = L.readReleaseLog(0, 10);
ok(log.count === 2 && log.tip === log.releases[1].hash, "a new release is appended and becomes the tip");
ok(C.logProblems(log.releases, "").length === 0, "the outside check agrees the log is in order");
ok(L.readReleaseLog(1, 10).releases.length === 1, "paging works");

// tampering
const t1 = JSON.parse(JSON.stringify(log.releases)); t1[0].release = t1[0].release.replace("aaa", "evil");
ok(C.logProblems(t1, "").some((p) => /fingerprint/.test(p)), "a changed release is caught");
const t2 = JSON.parse(JSON.stringify(log.releases)); t2.splice(0, 1); t2[0].seq = 1;
ok(C.logProblems(t2, "").length > 0, "a removed release is caught");
ok(C.appendOnlyProblems(log.releases, log.releases.slice(0, 1)).some((p) => /disappeared/.test(p)), "a mirror notices a release vanishing");
const t3 = JSON.parse(JSON.stringify(log.releases)); t3[0].hash = "f".repeat(64);
ok(C.appendOnlyProblems(log.releases, t3).some((p) => /changed/.test(p)), "a mirror notices history being rewritten");
ok(C.appendOnlyProblems(log.releases.slice(0, 1), log.releases).length === 0, "growing at the end is fine");
ok(C.logProblems(log.releases, "zs1.x.y").some((p) => /not signed/.test(p)), "unsigned releases are reported when a root key is given");

console.log(`All ${n} release log checks passed.`);

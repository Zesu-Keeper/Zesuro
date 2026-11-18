// The write guard: a server writes the record only if the root key delegated to it.
// Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/writer.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const tmp = fs.mkdtempSync(path.join(os.homedir(), ".zesuro-writer-test-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));
process.chdir(tmp);
fs.mkdirSync("data");
const { assertRecordWritable, resetWriterCache, writerStatus } = await import("../src/lib/writer.ts");

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const writable = () => { resetWriterCache(); try { assertRecordWritable(); return true; } catch (e) { return e.status === 503 ? false : (() => { throw e; })(); } };
const authorityFor = (...writers) => JSON.stringify({ v: 1, delegations: writers.map((w, i) => ({ head: JSON.stringify({ v: 1, type: "delegation", serial: i + 1, writer: w }), sig: "x" })) });

const ME = "m".repeat(43), OTHER = "o".repeat(43);
ok(writable(), "with no authority file, nothing is restricted (how the site started)");

fs.writeFileSync("data/authority.json", authorityFor(ME));
ok(!writable() && /no signing key yet/.test(writerStatus().why), "authority exists but this server has no key yet: read-only");

fs.writeFileSync("data/anchor-key.pub", ME + "\n");
ok(writable(), "this server's key is the delegated writer: writes allowed");

fs.writeFileSync("data/authority.json", authorityFor(ME, OTHER));
ok(!writable() && /not the writer/.test(writerStatus().why), "the root delegated to another server: this one is read-only");

fs.writeFileSync("data/authority.json", authorityFor(OTHER, ME));
ok(writable(), "and writes again if the root delegates back");

fs.writeFileSync("data/authority.json", "not json");
ok(!writable(), "an unreadable authority file fails closed");
fs.writeFileSync("data/authority.json", JSON.stringify({ v: 1, delegations: [] }));
ok(!writable() && /names no writer/.test(writerStatus().why), "an authority file with no delegations fails closed");

// The answer is cached briefly, not forever
fs.writeFileSync("data/authority.json", authorityFor(ME));
resetWriterCache();
ok(writerStatus().ok, "ok again");
fs.writeFileSync("data/authority.json", authorityFor(OTHER));
ok(writerStatus().ok, "a change is not seen inside the 5 second cache window");
resetWriterCache();
ok(!writerStatus().ok, "but is seen once it expires");

console.log(`All ${n} writer-guard checks passed`);

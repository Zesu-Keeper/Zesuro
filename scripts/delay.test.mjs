// Delayed release (lib/entries.ts): a sealed post waits, unpublished, and is written into the record later.
// Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/delay.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
process.chdir(fs.mkdtempSync(path.join(os.tmpdir(), "delay-")));
const E = await import(path.join(root, "src/lib/entries.ts"));
const TL = await import(path.join(root, "src/lib/timelock.ts"));
let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const hex = (b) => randomBytes(b).toString("hex");
const input = (extra = {}) => ({ uid: randomUUID(), title: "A title", text: "Something said, waiting to appear.", commitment: hex(32), nonce: hex(16), mode: "manual", revealAt: null, deadlineAt: null, commitV: 2, ...extra });

const now = Date.now();
const a = input();
const r = await E.sealEntry({ ...a, delay: "hours" });
ok(r.pending === true && r.uid === a.uid, "a delayed post is only acknowledged");
ok(r.releaseFrom >= now + E.DELAY_MIN - 1000 && r.releaseBy <= Date.now() + E.DELAY_MAX + 1000, "it gives the window it will appear in");
ok(E.isPending(a.uid), "it is waiting");
ok(E.getEntry(a.uid) === null, "it can't be opened yet");
ok(!E.listEntries({}).some((e) => e.uid === a.uid), "it is not listed yet");
ok(E.verifyChain().count === 0, "it is not in the chain yet");

await assert.rejects(() => E.sealEntry({ ...a, delay: "hours" }), /already exists/); n++;
const soon = Date.now() + 2 * 3_600_000;
const round = TL.roundForTime(soon);
const b = input({ mode: "date", revealAt: soon, timelock: { round, ct: TL.timelockEncrypt(new Uint8Array([1, 2, 3]), round) } });
await assert.rejects(() => E.sealEntry({ ...b, delay: "hours" }), /6 hours/, "a reveal sooner than the release window is refused"); n++;
const far = Date.now() + 9 * 3_600_000;
const round2 = TL.roundForTime(far);
const b2 = input({ mode: "date", revealAt: far, timelock: { round: round2, ct: TL.timelockEncrypt(new Uint8Array([1, 2, 3]), round2) } });
ok((await E.sealEntry({ ...b2, delay: "hours" })).pending, "a reveal after the window is fine");

const c = input();
const direct = await E.sealEntry(c);
ok(!direct.pending && direct.uid === c.uid && E.verifyChain().count === 1, "without the delay a post goes straight in");

ok(E.releasePending(Date.now()) === 0, "nothing is released before its time");
const later = Date.now() + E.DELAY_MAX + 1000;
ok(E.releasePending(later) === 2, "both waiting posts are released once their time has passed");
ok(!E.isPending(a.uid), "it is no longer waiting");
const got = E.getEntry(a.uid);
ok(got && got.createdAt >= later && got.text === a.text, "it is on the record, timed at its release");
const chain = E.verifyChain();
ok(chain.ok && chain.count === 3, "the chain is intact with them in");
ok(E.releasePending(later + 1000) === 0, "it is released only once");

console.log(`All ${n} delayed release checks passed.`);

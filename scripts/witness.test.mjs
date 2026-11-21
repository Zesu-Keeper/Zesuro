// Hash version 6: a post carries a drand beacon fetched just before posting, which proves it was made no earlier than that round.
// Uses two REAL past quicknet beacons (the same ones scripts/timelock-wire.test.mjs uses) and a stubbed clock.
// Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/witness.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ZERO, entryHash, entryProblem } from "./log-core.mjs";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "witness-"));
process.chdir(tmp);
const imp = (f) => import(path.join(root, "src/lib", f));
const [E, CC, CM, TL, MB] = await Promise.all([imp("entries.ts"), imp("client-crypto.ts"), imp("commit.ts"), imp("timelock.ts"), imp("mailbox.ts")]);
let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const refuses = async (p, re, m) => { await assert.rejects(p, re, m); n++; };

const SIG = {
  1000000: "83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72",
  2000000: "a7c94d62fa50475c65f259bc4d50afc0cebc5cb29848568f90dff842789c05d7f6b2414971a0b67bf532624ad6bab054",
};
const T1 = TL.timeOfRound(1000000);
const realNow = Date.now;
const clock = (t) => { Date.now = () => t; };

const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
const key = { priv: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d, ext: true, key_ops: ["sign"] }, pub: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true, key_ops: ["verify"] } };

let counter = 0;
async function manual(extra = {}) {
  const uid = crypto.randomUUID();
  const nonce = CC.randomHex(16);
  const title = `Witness test ${++counter}`;
  const text = `A unique thing said in witness test number ${counter} on ${uid}`;
  const content = { uid, title: CM.normTitle(title), text: CM.normText(text), placeMode: "none", place: null, secretCommit: null, mode: "manual" };
  const commitment = await CC.commitmentV2(key, nonce, content);
  return { uid, input: { uid, title: content.title, text: content.text, placeMode: "none", place: null, commitV: 2, commitment, nonce, mode: "manual", revealAt: null, deadlineAt: null, opening: null, secret: null, ...extra } };
}
function checkLog() {
  let prev = ZERO, count = 0;
  for (const x of E.listLog(0, 1000)) {
    if (entryProblem(x) || x.prevHash !== prev || entryHash(prev, x) !== x.entryHash) return { ok: false, at: x.seq, why: entryProblem(x) };
    prev = x.entryHash; count++;
  }
  return { ok: true, count };
}

clock(T1 + 5_000);
// ---- a post without a witness is unchanged
const plain = await manual();
const e0 = await E.sealEntry(plain.input);
ok(e0.hashVersion === 3 && e0.witness === null, "no witness: still hash v3, no witness shown");

// ---- a post with a witness
const w = await manual({ witness: { round: 1000000, sig: SIG[1000000] } });
const e1 = await E.sealEntry(w.input);
ok(e1.hashVersion === 6, "a witnessed post is hash v6");
ok(e1.witness?.round === 1000000 && e1.witness.sig === SIG[1000000] && e1.witness.notBefore === T1, "it shows the round, the signature and the not-before time");
ok(e1.createdAt >= e1.witness.notBefore, "the recorded time is after the witnessed moment");
const log1 = E.listLog(0, 10).find((x) => x.uid === w.uid);
ok(log1.hashV === 6 && log1.witnessRound === 1000000 && log1.witnessSig === SIG[1000000], "the public log carries the witness");
ok(E.verifyChain().ok && checkLog().ok, "the app's chain check and log-core's independent definition both pass");
ok(entryHash(log1.prevHash, { ...log1, witnessSig: SIG[2000000] }) !== log1.entryHash, "changing the signature changes the hash");
ok(entryHash(log1.prevHash, { ...log1, witnessRound: 2000000 }) !== log1.entryHash, "changing the round changes the hash");
ok(entryHash(log1.prevHash, { ...log1, witnessRound: null, witnessSig: null }) !== log1.entryHash, "removing the witness changes the hash");
ok(entryProblem({ ...log1, witnessSig: null }) === "bad time witness", "a v6 entry without a witness is refused by the checker");
ok(entryProblem({ ...log1, witnessSig: "zz" }) === "bad time witness", "a malformed signature is refused by the checker");

// ---- with private-reply mailbox keys too
const box = MB.makeMailbox();
const m = await manual({ witness: { round: 1000000, sig: SIG[1000000] }, mailbox: box.leaves });
const e2 = await E.sealEntry(m.input);
ok(e2.hashVersion === 6 && e2.mailboxRoot && e2.witness, "a post can have both a witness and mailbox keys");
ok(E.verifyChain().ok && checkLog().ok, "the chain still verifies");

// ---- fifty-two weekly mailbox keys
const wk = MB.makeMailbox(MB.WEEKS);
const wkPost = await manual({ witness: { round: 1000000, sig: SIG[1000000] }, mailbox: wk.leaves });
const e3 = await E.sealEntry(wkPost.input);
ok(e3.hashVersion === 6 && e3.mailboxRoot === MB.mailboxRootOf(wkPost.uid, wk.leaves), "a post with weekly mailbox keys is recorded, and the record fingerprints exactly those keys");
const INB = await imp("inbox.ts");
ok(INB.getMailbox(wkPost.uid)?.leaves.length === 52, "the server serves all fifty-two weekly keys");
const oddPost = await manual({ mailbox: wk.leaves.slice(0, 20) });
await refuses(E.sealEntry(oddPost.input), /private-reply keys are not valid/, "any other number of keys is refused");
ok(E.verifyChain().ok && checkLog().ok, "the chain verifies with weekly keys too");

// ---- a bad witness is refused, and nothing is recorded
const before = E.verifyChain().count;
const bad = async (witness, re, msg) => { const x = await manual({ witness }); await refuses(E.sealEntry(x.input), re, msg); };
await bad({ round: 1000000, sig: SIG[2000000] }, /time check/, "a signature for a different round");
await bad({ round: 1000000, sig: SIG[1000000].replace(/^./, (c) => (c === "0" ? "1" : "0")) }, /time check/, "an altered signature");
await bad({ round: 2000000, sig: SIG[2000000] }, /time check/, "a round that is in the future");
await bad({ round: 1000000, sig: "abc" }, /time check/, "a malformed signature");
await bad({ round: -5, sig: SIG[1000000] }, /time check/, "a bad round number");
await bad("nonsense", /time check/, "a witness that is not an object");
clock(T1 + 20 * 60_000);
await bad({ round: 1000000, sig: SIG[1000000] }, /time check/, "a beacon that is too old");
clock(T1 + 5_000);
ok(E.verifyChain().count === before, "refused posts leave no trace in the record");

// ---- delayed release keeps the witness
const d = await manual({ witness: { round: 1000000, sig: SIG[1000000] }, delay: "hours" });
const pend = await E.sealEntry(d.input);
ok(pend.pending === true, "a delayed post is queued");
clock(T1 + 8 * 3_600_000);
ok(E.releasePending(Date.now()) === 1, "it is released later");
clock(T1 + 8 * 3_600_000 + 1);
const got = E.getEntry(d.uid);
ok(got?.hashVersion === 6 && got.witness?.round === 1000000, "the released post is v6 and keeps its witness");
ok(E.verifyChain().ok && checkLog().ok, "the chain verifies after the release");

Date.now = realNow;
console.log(`All ${n} time witness checks passed.`);
process.exit(0);

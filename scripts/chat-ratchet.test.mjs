// Tests for the chat Double Ratchet: lib/chat-ratchet.ts (browser crypto, run here with Node's WebCrypto).
// Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/chat-ratchet.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
const imp = (f) => import(new URL("../src/lib/" + f, import.meta.url).pathname);
const [R, C] = await Promise.all([imp("chat-ratchet.ts"), imp("chat-crypto.ts")]);
let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const roomId = "11111111-2222-4333-8444-555555555555";

// the key exchange, as the real code does it
const inv = await C.newInvite(1);
const j = await C.joinWith(inv.secret, inv.hello, 0);
const accepted = await C.acceptJoin(inv.secret, inv.privs[0], j.roomId, j.join, 0);
ok(accepted && accepted.master === j.master, "both sides reach the same master");
ok(typeof j.ratchetPub === "string" && j.ratchetPriv, "the opener keeps a ratchet key pair");
ok(accepted.theirPub === j.ratchetPub, "the creator learns the opener's ratchet key");
ok(accepted.theirKem === j.kem.pk, "and the opener's post-quantum key");

let A = await R.startAsCreator(accepted.master, j.roomId, accepted.theirPub, accepted.theirKem);
let B = await R.startAsOpener(j.master, j.roomId, j.ratchetPriv, j.ratchetPub, j.kem);
const rid = j.roomId;
ok(R.canSend(A) && !R.canSend(B), "the creator can send first; the opener has to wait");

const send = async (side, body) => {
  const r = await R.ratchetEncrypt(side === "a" ? A : B, rid, body);
  if (side === "a") A = r.state; else B = r.state;
  return r;
};
const recv = async (side, blob) => {
  const r = await R.ratchetDecrypt(side === "a" ? A : B, rid, blob);
  if (r) { if (side === "a") A = r.state; else B = r.state; }
  return r;
};

// a normal conversation, both directions, several times
const m1 = await send("a", { kind: "hello" });
const r1 = await recv("b", m1.blob);
ok(r1 && r1.msg.kind === "hello" && r1.msg.from === "a" && r1.msg.v === 2, "opener reads the creator's first message");
ok(B.kemPk !== j.kem.pk && A.kemTheirs === j.kem.pk, "the opener retired its first post-quantum key after using it");
ok(R.canSend(B), "the opener can send after hearing from the creator");
const m2 = await send("b", { kind: "text", text: "hi from b" });
ok((await recv("a", m2.blob)).msg.text === "hi from b", "creator reads the reply");
for (let i = 0; i < 5; i++) {
  const x = await send("a", { kind: "text", text: `a${i}` });
  ok((await recv("b", x.blob)).msg.text === `a${i}`, `a to b #${i}`);
  const y = await send("b", { kind: "text", text: `b${i}` });
  ok((await recv("a", y.blob)).msg.text === `b${i}`, `b to a #${i}`);
}
ok(A.sent === 6 && B.sent === 6, "each side counts what it sent");

// the sender cannot read its own blob any more
ok((await R.ratchetDecrypt(A, rid, m1.blob)) === null, "a sender can't open its own message: the key is gone");

// replays and tampering
const x = await send("a", { kind: "text", text: "once" });
ok((await recv("b", x.blob)).msg.text === "once", "delivered once");
ok((await recv("b", x.blob)) === null, "a replay is refused");
const y2 = await send("b", { kind: "text", text: "tamper" });
const bad = y2.blob.slice(0, -4) + (y2.blob.slice(-4) === "AAAA" ? "BBBB" : "AAAA");
const before = JSON.stringify(A);
ok((await R.ratchetDecrypt(A, rid, bad)) === null, "an altered message is refused");
ok(JSON.stringify(A) === before, "a refused message leaves the state untouched");
ok((await recv("a", y2.blob)).msg.text === "tamper", "the genuine one still opens afterwards");
ok((await R.ratchetDecrypt(A, "99999999-2222-4333-8444-555555555555", (await send("b", { kind: "text", text: "wrong room" })).blob)) === null, "a message does not open in another room");

// out of order and dropped messages
const o1 = await send("a", { kind: "text", text: "o1" });
const o2 = await send("a", { kind: "text", text: "o2" });
const o3 = await send("a", { kind: "text", text: "o3" });
ok((await recv("b", o3.blob)).msg.text === "o3", "a later message opens first");
ok((await recv("b", o1.blob)).msg.text === "o1", "an earlier one opens afterwards");
ok((await recv("b", o2.blob)).msg.text === "o2", "and the one in between");
ok(Object.keys(B.skipped).length === 0, "skipped keys are used up");
// a long gap (messages the site no longer has) is accepted up to a limit, and refused beyond it, on a spare copy
{
  let FA = JSON.parse(JSON.stringify(A)), FB = JSON.parse(JSON.stringify(B));
  const blobs = [];
  for (let i = 0; i < R.MAX_SKIP + 3; i++) {
    const r = await R.ratchetEncrypt(FA, rid, { kind: "text", text: "f" + i });
    FA = r.state; blobs.push(r.blob);
  }
  ok((await R.ratchetDecrypt(FB, rid, blobs[blobs.length - 1])) === null, "jumping too far ahead is refused");
  const mid = await R.ratchetDecrypt(FB, rid, blobs[R.MAX_SKIP - 1]);
  ok(mid && mid.msg.text === "f" + (R.MAX_SKIP - 1), "a big gap up to the limit still opens");
  const early = await R.ratchetDecrypt(mid.state, rid, blobs[5]);
  ok(early && early.msg.text === "f5", "an earlier one that was skipped over can still be opened later");
}

// forward secrecy: a thief who takes the state now cannot open earlier messages
const e1 = await send("a", { kind: "text", text: "secret one" });
const e2 = await send("b", { kind: "text", text: "secret two" });
await recv("b", e1.blob); await recv("a", e2.blob);
const e3 = await send("a", { kind: "text", text: "later" });
await recv("b", e3.blob);
const stolenA = JSON.parse(JSON.stringify(A)), stolenB = JSON.parse(JSON.stringify(B));
ok((await R.ratchetDecrypt(stolenB, rid, e1.blob)) === null, "stolen opener state can't open an earlier message");
ok((await R.ratchetDecrypt(stolenA, rid, e2.blob)) === null, "stolen creator state can't open an earlier reply");
// even with the master key too
const rootAgain = await R.rootFromMaster(accepted.master, rid);
ok(rootAgain !== stolenA.rk && rootAgain !== stolenB.rk, "the root key has moved on from the one the master gives");

// post-compromise: a thief who copied ONE side's state can follow the chat only until both sides have replied to each
// other a couple of times, because each reply mixes in a fresh key the thief never had
const heal = JSON.parse(JSON.stringify(A));
for (let i = 0; i < 3; i++) {
  const y = await send("b", { kind: "text", text: "heal b" + i });
  await recv("a", y.blob);
  const x2 = await send("a", { kind: "text", text: "heal a" + i });
  await recv("b", x2.blob);
}
const e6 = await send("b", { kind: "text", text: "after healing" });
ok((await R.ratchetDecrypt(heal, rid, e6.blob)) === null, "a copy of one side's old state can't follow the chat after a few exchanges");
await recv("a", e6.blob);

// the message count and sender inside are right
const cnt = await send("a", { kind: "text", text: "count" });
const got = await recv("b", cnt.blob);
ok(got.msg.n === A.sent - 1 && got.msg.from === "a", "the running number inside the message is the sender's");

// blobs are padded, and a text message fits the server's size limit
const big = await send("a", { kind: "text", text: "x".repeat(4000) });
ok(big.blob.length < 46_000, "the largest message fits what the server accepts");
ok((await recv("b", big.blob)).msg.text.length === 4000, "a long message opens");
const small = await send("a", { kind: "text", text: "a" });
const small2 = await send("a", { kind: "text", text: "a much longer message than the one before it, with quite a few more words in it" });
ok(small.blob.length === small2.blob.length, "short messages are padded to the same size");
await recv("b", small.blob); await recv("b", small2.blob);

// one side gets two chats: states are independent
const inv2 = await C.newInvite(1);
const j2 = await C.joinWith(inv2.secret, inv2.hello, 0);
const acc2 = await C.acceptJoin(inv2.secret, inv2.privs[0], j2.roomId, j2.join, 0);
const A2 = await R.startAsCreator(acc2.master, j2.roomId, acc2.theirPub, acc2.theirKem);
const first2 = await R.ratchetEncrypt(A2, j2.roomId, { kind: "hello" });
ok((await R.ratchetDecrypt(B, j2.roomId, first2.blob)) === null, "a message from another chat does not open here");

// the post-quantum layer: breaking every Diffie-Hellman key is not enough without the ML-KEM secret
{
  const y = await R.ratchetEncrypt(B, rid, { kind: "text", text: "ping" });
  B = y.state;
  const ya = await R.ratchetDecrypt(A, rid, y.blob); A = ya.state; // A starts a new run, locked to B's ML-KEM key
  const q = await R.ratchetEncrypt(A, rid, { kind: "text", text: "quantum" });
  A = q.state;
  const crippled = JSON.parse(JSON.stringify(B));
  crippled.kemSk = R.kemPair().sk; // as if someone had every DH secret but not B's ML-KEM secret
  ok((await R.ratchetDecrypt(crippled, rid, q.blob)) === null, "without the post-quantum secret the new run can't be opened");
  const r = await R.ratchetDecrypt(B, rid, q.blob);
  ok(r && r.msg.text === "quantum", "with it, it opens");
  B = r.state;
}
console.log(`All ${n} chat ratchet checks passed.`);

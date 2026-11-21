// Private replies: lib/mailbox.ts. Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/mailbox.test.mjs
import assert from "node:assert/strict";
const M = await import(new URL("../src/lib/mailbox.ts", import.meta.url).pathname);
let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const uid = "11111111-2222-4333-8444-555555555555";
const box = M.makeMailbox();
ok(box.leaves.length === 12 && box.secrets.length === 12, "twelve months of keys");
ok(M.parseMailboxLeaves(box.leaves)?.length === 12, "the public keys have the right shape");
ok(M.parseMailboxLeaves(box.leaves.slice(0, 11)) === null && M.parseMailboxLeaves([...box.leaves.slice(0, 11), { x: "a", k: "b" }]) === null, "a wrong shape is refused");
const root = M.mailboxRootOf(uid, box.leaves);
ok(/^[0-9a-f]{64}$/.test(root), "the fingerprint is a hash");
const swapped = [...box.leaves]; swapped[3] = M.makeMailbox().leaves[3];
ok(M.mailboxRootOf(uid, swapped) !== root, "swapping one month's key changes the fingerprint");
ok(M.mailboxRootOf("99999999-2222-4333-8444-555555555555", box.leaves) !== root, "the fingerprint is tied to the post");

const body = JSON.stringify({ v: 1, invite: "A".repeat(43), text: "Can we talk?" });
const blob = M.sealReply(uid, box.leaves, 2, body);
const got = M.openReply(uid, box.secrets, blob);
ok(got && got.idx === 2 && got.plain === body, "the author opens a reply");
ok(M.parseReplyBody(got.plain)?.text === "Can we talk?", "and reads it");
ok(M.openReply(uid, M.makeMailbox().secrets, blob) === null, "someone else's keys open nothing");
ok(M.openReply("99999999-2222-4333-8444-555555555555", box.secrets, blob) === null, "a reply for one post doesn't open as another");
const bad = blob.slice(0, -6) + (blob.slice(-6) === "AAAAAA" ? "BBBBBB" : "AAAAAA");
ok(M.openReply(uid, box.secrets, bad) === null, "an altered reply is refused");
const expired = M.expireSecrets(box.secrets, Date.now() - 4 * M.MONTH_MS, Date.now());
ok(expired[2].x === null && M.openReply(uid, expired, blob) === null, "once a month's key is thrown away its replies can't be opened");
ok(expired[5].x !== null, "later months are kept");
ok(M.monthIndex(1000, 1000) === 0 && M.monthIndex(1000, 1000 + 13 * M.MONTH_MS) === -1 && M.monthIndex(1000, 1000 + 2.5 * M.MONTH_MS) === 2, "months are counted from the post's time");
ok(M.parseReplyBody('{"v":1,"invite":"short","text":"x"}') === null, "a reply without a proper chat link is refused");
ok(blob.length < 8000, "a reply is small enough to send");

// ---- weekly keys (52), for very sensitive posts
{
  const wk = M.makeMailbox(M.WEEKS);
  ok(wk.leaves.length === 52 && wk.secrets.length === 52, "fifty-two weekly keys");
  ok(M.parseMailboxLeaves(wk.leaves)?.length === 52, "weekly public keys have a valid shape");
  ok(M.parseMailboxLeaves(wk.leaves.slice(0, 40)) === null, "any other count is refused");
  ok(M.mailboxRootOf(uid, wk.leaves) !== M.mailboxRootOf(uid, box.leaves), "the fingerprint depends on the keys, so the period cannot be swapped");
  ok(M.monthIndex(1000, 1000 + 3.5 * M.WEEK_MS, 52) === 3 && M.monthIndex(1000, 1000 + 53 * M.WEEK_MS, 52) === -1, "a weekly key lasts a week and the year ends after 52");
  ok(M.monthIndex(1000, 1000 + 3.5 * M.WEEK_MS) === 0, "the same time on a monthly post is still month 0");
  const gone = M.expireSecrets(wk.secrets, Date.now() - 3 * M.WEEK_MS, Date.now());
  ok(gone[0].x === null && gone[1].x === null && gone[2].x !== null && gone[5].x !== null, "weekly keys of past weeks are thrown away, with two days' grace");
  let threw = false; try { M.makeMailbox(7); } catch { threw = true; }
  ok(threw, "other sizes can't be made");
  const blob = M.sealReply(uid, wk.leaves, 5, "hello weekly");
  const opened = M.openReply(uid, wk.secrets, blob);
  ok(opened?.idx === 5 && opened.plain === "hello weekly", "a reply locked to week 5 opens with the author's keys");
  const kept = wk.secrets.map((x, i) => (i === 5 ? { x: null, k: null } : x));
  ok(M.openReply(uid, kept, blob) === null, "once that week's key is thrown away, the reply can never be opened");
}

console.log(`All ${n} mailbox checks passed.`);

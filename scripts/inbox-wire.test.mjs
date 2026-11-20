// Private replies end to end on the server code: a post sealed with mailbox keys (hash v5), the public log, the
// mailbox endpoint's data, a locked reply, the shared inbox, and the author opening it.
// Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/inbox-wire.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
process.chdir(fs.mkdtempSync(path.join(os.tmpdir(), "inbox-")));
const [E, I, M, LC] = await Promise.all([import(path.join(root, "src/lib/entries.ts")), import(path.join(root, "src/lib/inbox.ts")), import(path.join(root, "src/lib/mailbox.ts")), import(path.join(root, "scripts/log-core.mjs"))]);
let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const hex = (b) => randomBytes(b).toString("hex");
const input = (extra = {}) => ({ uid: randomUUID(), title: "A post", text: "Said with a private mailbox " + hex(4) + ".", commitment: hex(32), nonce: hex(16), mode: "manual", revealAt: null, deadlineAt: null, commitV: 2, ...extra });

const plain = await E.sealEntry(input());
ok(plain.mailboxRoot === null, "a post without a mailbox has no fingerprint");
const box = M.makeMailbox();
const a = input();
const sealed = await E.sealEntry({ ...a, mailbox: box.leaves });
ok(sealed.mailboxRoot === M.mailboxRootOf(a.uid, box.leaves), "the record holds the mailbox fingerprint the author expects");
await assert.rejects(() => E.sealEntry({ ...input(), mailbox: box.leaves.slice(0, 3) }), /private-reply keys/); n++;

// the public log and an outside check
const log = E.listLog(0, 100);
const last = log.at(-1);
ok(last.hashV === 5 && last.mailboxRoot === sealed.mailboxRoot, "the log carries version 5 with the fingerprint");
let prev = "0".repeat(64);
for (const x of log) { ok(!LC.entryProblem(x) && LC.entryHash(prev, x) === x.entryHash, `entry ${x.seq} verifies from outside`); prev = x.entryHash; }
ok(E.verifyChain().ok, "the chain verifies");

// a reader fetches the mailbox, checks it, and replies
const mb = I.getMailbox(a.uid);
ok(mb && M.mailboxRootOf(a.uid, mb.leaves) === last.mailboxRoot, "the mailbox keys match the record's fingerprint");
ok(I.getMailbox(plain.uid) === null, "a post without a mailbox has none");
const idx = M.monthIndex(mb.createdAt, Date.now());
const body = JSON.stringify({ v: 1, invite: "B".repeat(43), text: "I'm a reporter. Can we talk?" });
I.postReply(a.uid, M.sealReply(a.uid, mb.leaves, idx, body));
assert.throws(() => I.postReply(plain.uid, "AAAA"), /doesn't take private replies/); n++;
assert.throws(() => I.postReply(a.uid, "not base64!"), /not valid/); n++;

// everyone fetches the same inbox; only the author can open their reply
const inbox = I.readInbox(0);
ok(inbox.messages.length === 1 && inbox.messages[0].uid === a.uid, "the shared inbox holds the locked reply");
const opened = M.openReply(a.uid, box.secrets, inbox.messages[0].blob);
ok(opened && M.parseReplyBody(opened.plain).text === "I'm a reporter. Can we talk?", "the author opens it");
ok(M.openReply(a.uid, M.makeMailbox().secrets, inbox.messages[0].blob) === null, "nobody else can");
ok(I.readInbox(inbox.messages[0].id).messages.length === 0, "paging past it gives nothing new");
console.log(`All ${n} private reply wire checks passed.`);

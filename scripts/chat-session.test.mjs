// Integration test for a whole private chat: the real key exchange, the real server code (lib/chat.ts, on a
// temporary database), the forward-secret ratchet and each device's own storage (lib/chat-session.ts).
// Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/chat-session.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "chat-session-"));
process.chdir(tmp); // the server code keeps its database in ./data

// two devices, each with its own permanent and session storage; `as()` switches which one the code sees
function storage() {
  const m = new Map();
  return { m, getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => void m.set(k, String(v)), removeItem: (k) => void m.delete(k), key: (i) => [...m.keys()][i] ?? null, get length() { return m.size; } };
}
const dev = { A: { l: storage(), s: storage() }, B: { l: storage(), s: storage() } };
const as = (d) => { globalThis.localStorage = dev[d].l; globalThis.sessionStorage = dev[d].s; };
as("A");

const imp = (f) => import(path.join(root, "src/lib", f));
const [C, SRV, SESS, ST] = await Promise.all([imp("chat-crypto.ts"), imp("chat.ts"), imp("chat-session.ts"), imp("chat-store.ts")]);

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };

// the site, as seen by the browser
globalThis.fetch = async (url, init = {}) => {
  const u = new URL(url, "http://x");
  const auth = init.headers?.["x-chat-auth"];
  const m = /^\/api\/chat\/rooms\/([0-9a-f-]{36})$/.exec(u.pathname);
  const reply = (status, body) => ({ ok: status < 400, status, json: async () => body });
  try {
    if (m && (init.method ?? "GET") === "GET") return reply(200, SRV.readRoom(m[1], auth, Number(u.searchParams.get("after") ?? "0")));
    if (m && init.method === "POST") return reply(201, SRV.postMessage(m[1], auth, JSON.parse(init.body).blob));
    return reply(404, {});
  } catch (e) {
    return reply(e.status ?? 500, { error: e.message });
  }
};

// ---- the key exchange, as the pages do it
async function makeChat({ memA = false, memB = false } = {}) {
  as("A");
  const inv = await C.newInvite(1);
  SRV.createInvite({ id: inv.id, owner: inv.ownerHash, hello: inv.hello, maxUses: 1 });
  as("B");
  const j = await C.joinWith(inv.secret, inv.hello, 0);
  const roomB = { id: j.roomId, role: "b", master: j.master, createdAt: Date.now(), v: 2, ...(memB ? { mem: true } : {}) };
  ok(await SESS.startRoom(roomB, { kind: "opener", priv: j.ratchetPriv, pub: j.ratchetPub }), "the opener's state is saved");
  SRV.joinInvite(inv.id, { room: j.roomId, join: j.join, auth: j.authHash, slot: 0 });
  as("A");
  const st = SRV.inviteStatus(inv.id, inv.ownerSecret);
  const got = await C.acceptJoin(inv.secret, inv.privs[0], st.rooms[0].id, st.rooms[0].join, 0);
  const roomA = { id: st.rooms[0].id, role: "a", master: got.master, createdAt: Date.now(), v: 2, ...(memA ? { mem: true } : {}) };
  ok(await SESS.startRoom(roomA, { kind: "creator", theirPub: got.theirPub }), "the creator's state is saved");
  return { roomA, roomB, keysA: await C.roomKeys(got.master, roomA.id), keysB: await C.roomKeys(j.master, roomB.id) };
}

const { roomA, roomB, keysA, keysB } = await makeChat();
ok(roomA.id === roomB.id && keysA.token === keysB.token, "both sides agree on the chat");

// the opener cannot speak first, the creator's hello unlocks that
as("B");
let sB = await SESS.loadSnapshot(roomB);
ok(sB && !sB.canSend && sB.items.length === 0, "the opener can't send before hearing from the creator");
as("A");
await SESS.ensureHello(roomA, keysA);
await SESS.ensureHello(roomA, keysA); // twice: must not send a second one
const a1 = await SESS.pollRoom(roomA, keysA);
ok(a1.items.length === 1 && a1.items[0].own && a1.items[0].msg.kind === "hello", "the creator's own hello is in its history");
as("B");
sB = await SESS.pollRoom(roomB, keysB);
ok(sB.items.length === 1 && sB.items[0].msg.kind === "hello" && sB.canSend, "the opener reads the hello and can now send");

// a conversation, both ways
as("B");
await SESS.sendMessage(roomB, keysB, { kind: "text", text: "hello from B" });
as("A");
let sA = await SESS.pollRoom(roomA, keysA);
ok(sA.items.some((i) => i.msg?.kind === "text" && i.msg.text === "hello from B" && !i.own), "the creator reads the opener's message");
sA = await SESS.sendMessage(roomA, keysA, { kind: "text", text: "hello from A" });
ok(sA.items.at(-1).own && sA.items.at(-1).msg.text === "hello from A", "a sent message goes straight into the history");
sA = await SESS.pollRoom(roomA, keysA);
ok(sA.items.filter((i) => i.msg?.kind === "text").length === 2, "polling does not duplicate what was sent");
ok(sA.items.every((i, k, a) => k === 0 || a[k - 1].id < i.id), "the history is in order");
as("B");
sB = await SESS.pollRoom(roomB, keysB);
ok(sB.items.some((i) => i.msg?.text === "hello from A"), "the opener reads the reply");
const again = await SESS.pollRoom(roomB, keysB);
ok(again.items.length === sB.items.length, "a second poll changes nothing");

// the history is on the device, so it survives a restart, and nothing about it is on the site in readable form
const local = await SESS.loadSnapshot(roomB);
ok(local.items.length === sB.items.length && local.items.some((i) => i.msg?.text === "hello from A"), "the history is read back from the device");
const stored = JSON.stringify([...dev.B.l.m.values(), ...dev.B.s.m.values()]);
ok(stored.includes("hello from A"), "the history lives on the device");
const server = SRV.readRoom(roomB.id, keysB.token, 0);
ok(!JSON.stringify(server).includes("hello from"), "the site holds only scrambled blobs");

// junk from the server or a stranger is shown as unreadable and does not break the chat
SRV.postMessage(roomB.id, keysB.token, "A".repeat(200));
as("A");
await SESS.sendMessage(roomA, keysA, { kind: "text", text: "after the junk" });
as("B");
sB = await SESS.pollRoom(roomB, keysB);
ok(sB.items.some((i) => i.msg === null), "a blob that isn't a message is kept as unreadable");
ok(sB.items.some((i) => i.msg?.text === "after the junk"), "and real messages after it still open");

// a message sent twice by the site opens only once
const blobs = SRV.readRoom(roomB.id, keysB.token, 0).messages;
const lastGood = blobs.at(-1);
SRV.postMessage(roomB.id, keysB.token, lastGood.blob);
sB = await SESS.pollRoom(roomB, keysB);
ok(sB.items.filter((i) => i.msg?.text === "after the junk").length === 1, "a replayed message is not shown twice");

// a session-only chat keeps nothing in permanent storage
const sess = await makeChat({ memA: true, memB: true });
as("A");
await SESS.ensureHello(sess.roomA, sess.keysA);
as("B");
await SESS.pollRoom(sess.roomB, sess.keysB);
await SESS.sendMessage(sess.roomB, sess.keysB, { kind: "text", text: "tab only" });
ok(![...dev.B.l.m.keys()].some((k) => k.includes(sess.roomB.id)), "a session-only chat leaves nothing in permanent storage");
ok([...dev.B.s.m.keys()].some((k) => k.includes(sess.roomB.id)), "it is in session storage");
dev.B.s.m.clear();
ok((await SESS.loadSnapshot(sess.roomB)) === null, "closing the tab erases it");

// the delete timer also applies to what is kept on the device
as("A");
const db = (await imp("db.ts")).getDb();
db.prepare("UPDATE chat_rooms SET ttl_ms = 60000 WHERE id = ?").run(roomA.id);
const old = JSON.parse(dev.A.l.getItem(ST.STATE_PREFIX + roomA.id));
old.items[0].at = Date.now() - 120_000;
dev.A.l.setItem(ST.STATE_PREFIX + roomA.id, JSON.stringify(old));
const aged = await SESS.pollRoom(roomA, keysA);
ok(aged.ttl === 60000 && aged.items.every((i) => i.at >= Date.now() - 61_000), "messages older than the timer are dropped from the device");

// ending the chat
SRV.deleteRoom(roomA.id, keysA.token);
as("B");
const ended = await SESS.pollRoom(roomB, keysB);
ok(ended.gone === "deleted", "the other side learns the chat was ended");

console.log(`All ${n} chat session checks passed.`);

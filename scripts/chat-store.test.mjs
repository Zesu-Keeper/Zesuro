// Tests for the chat store (lib/chat-store.ts): session-only chats, the passcode lock, encrypted chat state.
// The browser's storage is replaced by plain in-memory stand-ins.
// Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/chat-store.test.mjs
import assert from "node:assert/strict";
const imp = (f) => import(new URL("../src/lib/" + f, import.meta.url).pathname);
const S = await imp("chat-store.ts");
let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };

function kv() {
  const m = new Map();
  return { m, getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => void m.set(k, String(v)), removeItem: (k) => void m.delete(k), keys: () => [...m.keys()] };
}
const room = (id, extra = {}) => ({ id, role: "a", master: "M".repeat(43), createdAt: 1, v: 2, ...extra });
const inv = (id, extra = {}) => ({ secret: "s".repeat(43), id, ownerSecret: "o", privs: [{ kty: "EC" }], maxUses: 1, createdAt: 1, ...extra });
const state = (marker) => ({ v: 2, ratchet: { v: 2, marker }, cursor: 3, own: [], items: [{ id: 1, at: 1, msg: null }] });

// ---- plain storage, session-only chats
{
  const L = kv(), Se = kv();
  const st = S.createChatStore(L, Se);
  ok(st.addRoom(room("r1")), "a chat is stored");
  ok(st.addRoom(room("r2", { mem: true })), "a session-only chat is stored");
  ok(L.getItem(S.INDEX).includes("r1") && !L.getItem(S.INDEX).includes("r2"), "the permanent index holds only the permanent chat");
  ok(Se.getItem(S.SESSION_INDEX).includes("r2") && !Se.getItem(S.SESSION_INDEX).includes("r1"), "the session index holds only the session chat");
  const all = st.loadChats();
  ok(all.rooms.length === 2 && all.rooms.find((r) => r.id === "r2").mem === true, "both are listed, the session one marked");
  st.addInvite(inv("i1", { mem: true }));
  ok(!L.getItem(S.INDEX).includes("i1") && Se.getItem(S.SESSION_INDEX).includes("i1"), "a session-only link is kept for this tab only");
  ok(st.eraseInviteKey("i1", 0) && st.loadChats().invites[0].privs[0] === null, "a link key can be erased");
  ok(await st.saveRoomState("r1", false, state("p")) && L.keys().includes(S.STATE_PREFIX + "r1"), "a chat's state is stored permanently");
  ok(await st.saveRoomState("r2", true, state("s")) && Se.keys().includes(S.STATE_PREFIX + "r2") && !L.keys().includes(S.STATE_PREFIX + "r2"), "a session chat's state never reaches permanent storage");
  ok((await st.loadRoomState("r2", true)).ratchet.marker === "s", "state reads back");
  // closing the tab: the session storage is gone
  const st2 = S.createChatStore(L, kv());
  ok(st2.loadChats().rooms.length === 1 && st2.loadChats().rooms[0].id === "r1", "after the tab closes only the permanent chat remains");
  ok((await st2.loadRoomState("r2", true)) === null, "and the session chat's state is gone");
  st.dropRoom("r1");
  ok(!L.keys().includes(S.STATE_PREFIX + "r1") && !st.findRoom("r1"), "dropping a chat removes its state too");
  ok(st.keepMode() === "device", "chats are kept on the device by default");
  st.setKeepMode("session");
  ok(st.keepMode() === "session" && L.getItem(S.MODE_KEY) === "session", "the choice to keep chats only for the tab is remembered");
}

// ---- the passcode
{
  const L = kv(), Se = kv();
  const st = S.createChatStore(L, Se);
  st.addRoom(room("r1"));
  st.addRoom(room("r2", { mem: true }));
  await st.saveRoomState("r1", false, state("secret-state"));
  await st.saveRoomState("r2", true, state("session-state"));
  ok(!(await st.setPasscode("short", 5, 1000)), "a short passcode is refused");
  ok(await st.setPasscode("correct horse battery", 5, 1000), "a passcode can be set");
  ok(st.lockConfigured() && !st.isLocked() && st.autoLockMinutes() === 5, "the chats stay open right after setting it");
  const dump = [...L.m.values(), ...Se.m.values()].join("\n");
  ok(!dump.includes("secret-state") && !dump.includes("session-state") && !dump.includes('"r1"') && !dump.includes('"r2"'), "nothing readable is left in storage");
  ok(st.findRoom("r1") && st.findRoom("r2"), "the chats still work while unlocked");
  ok(st.addRoom(room("r3")), "new chats can be added while unlocked");
  await st.flush();
  ok(!L.getItem(S.INDEX).includes("r3"), "and are stored locked too");
  st.lockNow();
  ok(st.isLocked() && st.loadChats().rooms.length === 0, "locking forgets the chats in memory");
  ok(!st.addRoom(room("r4")), "nothing can be added while locked");
  ok((await st.loadRoomState("r1", false)) === null, "no state can be read while locked");
  ok(!(await st.unlock("wrong passcode here")) && st.isLocked(), "a wrong passcode does not unlock");
  ok(await st.unlock("correct horse battery") && !st.isLocked(), "the right passcode unlocks");
  ok(st.loadChats().rooms.length === 3, "the chats are back");
  ok((await st.loadRoomState("r1", false)).ratchet.marker === "secret-state", "state is readable again");
  ok((await st.loadRoomState("r2", true)).ratchet.marker === "session-state", "session state is readable again");
  // a fresh start of the browser: locked until the passcode is entered
  const st2 = S.createChatStore(L, Se);
  ok(st2.isLocked() && st2.loadChats().rooms.length === 0, "a restarted browser starts locked");
  ok(await st2.unlock("correct horse battery") && st2.loadChats().rooms.length === 3, "and opens with the passcode");
  // change the passcode
  ok(await st2.setPasscode("a different long passcode", 15, 1000), "the passcode can be changed");
  const st3 = S.createChatStore(L, Se);
  ok(!(await st3.unlock("correct horse battery")), "the old passcode no longer works");
  ok(await st3.unlock("a different long passcode") && st3.autoLockMinutes() === 15, "the new one does");
  ok((await st3.loadRoomState("r1", false)).ratchet.marker === "secret-state", "state survived the change");
  // remove it
  ok(!(await st3.removePasscode("nope nope nope")), "removing it needs the passcode");
  ok(await st3.removePasscode("a different long passcode"), "it can be removed");
  ok(!st3.lockConfigured() && L.getItem(S.LOCK_KEY) === null, "the setting is gone");
  const st4 = S.createChatStore(L, Se);
  ok(!st4.isLocked() && st4.loadChats().rooms.length === 3, "the chats open without it again");
  ok((await st4.loadRoomState("r1", false)).ratchet.marker === "secret-state", "plain state reads back");
  // erasing
  st4.wipeChats();
  ok(st4.loadChats().rooms.length === 0 && ![...L.keys(), ...Se.keys()].some((k) => k.startsWith("whenisaid.chat") && k !== S.MODE_KEY), "erasing removes every chat and its state");
}

// ---- storage that refuses to write
{
  const L = kv(); L.setItem = () => { throw new Error("quota"); };
  const st = S.createChatStore(L, kv());
  ok(st.addRoom(room("x")) === false, "a browser that refuses to store is reported");
}

console.log(`All ${n} chat store checks passed.`);

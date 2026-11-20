// Browser only. Runs one private chat: fetches what the other person sent, opens it, writes down what this
// side sends, and keeps the chat's history on this device. Because every message can be opened only once
// (lib/chat-ratchet.ts), the history is kept here, not re-read from the site.

import type { Body, Message, RoomKeys } from "./chat-crypto";
import { site } from "./site";
import { canSend, ratchetDecrypt, ratchetEncrypt, startAsCreator, startAsOpener } from "./chat-ratchet";
import { loadRoomState, saveRoomState, type RoomState, type StoredItem, type StoredRoom } from "./chat-store";

export type Item = StoredItem;

export interface Snapshot {
  items: Item[];
  ttl: number;
  /** True once this side is able to send (the person who opened the link has to hear from the other first). */
  canSend: boolean;
  gone: null | "deleted" | "missing";
}

// One thing at a time per chat: a poll and a send must never both change the ratchet.
const queues = new Map<string, Promise<unknown>>();
function exclusive<T>(id: string, fn: () => Promise<T>): Promise<T> {
  const prev = queues.get(id) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  queues.set(id, run.catch(() => {}));
  return run;
}

type Start =
  | { kind: "creator"; theirPub: string }
  | { kind: "opener"; priv: JsonWebKey; pub: string };

/** Makes a chat's first state, right after the key exchange. */
export async function startRoom(room: StoredRoom, start: Start): Promise<boolean> {
  const ratchet =
    start.kind === "creator"
      ? await startAsCreator(room.master, room.id, start.theirPub)
      : await startAsOpener(room.master, room.id, start.priv, start.pub);
  return saveRoomState(room.id, !!room.mem, { v: 2, ratchet, cursor: 0, own: [], items: [] });
}

const snap = (s: RoomState, ttl: number, gone: Snapshot["gone"] = null): Snapshot => ({
  items: s.items,
  ttl,
  canSend: canSend(s.ratchet),
  gone,
});

/** What is already on this device, without asking the site. */
export async function loadSnapshot(room: StoredRoom): Promise<Snapshot | null> {
  const s = await loadRoomState(room.id, !!room.mem);
  return s ? snap(s, 0) : null;
}

const byId = (a: Item, b: Item) => a.id - b.id;

/** Fetches and opens everything new. Safe to call as often as you like. */
export function pollRoom(room: StoredRoom, keys: RoomKeys): Promise<Snapshot> {
  return exclusive(room.id, async () => {
    const st = await loadRoomState(room.id, !!room.mem);
    if (!st) return { items: [], ttl: 0, canSend: false, gone: "missing" as const };
    let ttl = 0;
    for (;;) {
      const r = await fetch(site(`/api/chat/rooms/${room.id}?after=${st.cursor}`), {
        cache: "no-store",
        headers: { "x-chat-auth": keys.token },
      });
      if (r.status === 410) return snap(st, ttl, "deleted");
      if (r.status === 404) return snap(st, ttl, "missing");
      if (!r.ok) throw new Error("Could not reach the server");
      const d = (await r.json()) as { ttl: number; more: boolean; messages: { id: number; blob: string; at: number }[] };
      ttl = d.ttl;
      for (const m of d.messages) {
        if (st.own.includes(m.id) || st.items.some((i) => i.id === m.id)) continue; // ours, or already dealt with
        const res = await ratchetDecrypt(st.ratchet, room.id, m.blob);
        if (res) {
          st.ratchet = res.state;
          st.items.push({ id: m.id, at: m.at, msg: res.msg });
        } else st.items.push({ id: m.id, at: m.at, msg: null });
      }
      if (d.messages.length) st.cursor = d.messages[d.messages.length - 1].id;
      st.own = st.own.filter((x) => x > st.cursor);
      // A delete timer on the site also applies to what is kept here.
      if (ttl > 0) st.items = st.items.filter((i) => i.at >= Date.now() - ttl);
      st.items.sort(byId);
      if (!(await saveRoomState(room.id, !!room.mem, st))) throw new Error("This browser would not save the chat");
      if (!d.more) break;
    }
    return snap(st, ttl);
  });
}

/** Locks one message, sends it and writes it into the history. */
export function sendMessage(room: StoredRoom, keys: RoomKeys, body: Body): Promise<Snapshot> {
  return exclusive(room.id, async () => {
    const st = await loadRoomState(room.id, !!room.mem);
    if (!st) throw new Error("This chat isn't on this device any more");
    const out = await ratchetEncrypt(st.ratchet, room.id, body);
    // Save first: the key that locked this message is already spent, and must never be used twice.
    st.ratchet = out.state;
    if (!(await saveRoomState(room.id, !!room.mem, st))) throw new Error("This browser would not save the chat");
    const res = await fetch(site(`/api/chat/rooms/${room.id}`), {
      method: "POST",
      headers: { "content-type": "application/json", "x-chat-auth": keys.token },
      body: JSON.stringify({ blob: out.blob }),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      throw new Error((d as { error?: string }).error || "Could not send");
    }
    const sent = (await res.json()) as { id: number; at: number };
    st.own.push(sent.id);
    st.items.push({ id: sent.id, at: sent.at, msg: out.msg as Message, own: true });
    st.items.sort(byId);
    await saveRoomState(room.id, !!room.mem, st);
    return snap(st, 0);
  });
}

/** The person who made the link says a first, invisible hello, so the other person can reply straight away. */
export async function ensureHello(room: StoredRoom, keys: RoomKeys): Promise<void> {
  if (room.role !== "a") return;
  const st = await loadRoomState(room.id, !!room.mem);
  if (!st || st.ratchet.sent > 0 || !canSend(st.ratchet)) return;
  // Re-check inside the queue: two callers must not both send one.
  await exclusive(room.id, async () => {
    const again = await loadRoomState(room.id, !!room.mem);
    if (!again || again.ratchet.sent > 0) return;
    const out = await ratchetEncrypt(again.ratchet, room.id, { kind: "hello" });
    again.ratchet = out.state;
    if (!(await saveRoomState(room.id, !!room.mem, again))) return;
    const res = await fetch(site(`/api/chat/rooms/${room.id}`), {
      method: "POST",
      headers: { "content-type": "application/json", "x-chat-auth": keys.token },
      body: JSON.stringify({ blob: out.blob }),
    });
    if (!res.ok) return;
    const sent = (await res.json()) as { id: number; at: number };
    again.own.push(sent.id);
    again.items.push({ id: sent.id, at: sent.at, msg: out.msg as Message, own: true });
    await saveRoomState(room.id, !!room.mem, again);
  });
}

// Browser only. Private chats this browser takes part in. The keys live here and nowhere
// else: clear this browser's storage and the chats can no longer be read by anyone on it.

import { fromB64u, toB64u, type Role } from "./chat-crypto";

const STORE = "whenisaid.chats.v1";
const ACCESS_PREFIX = "zesuro-chat:v1:";

/** A link this browser made that can still be opened by someone. */
export interface StoredInvite {
  secret: string;
  id: string;
  ownerSecret: string;
  /** One private key per use of the link. A slot is erased (null) as soon as its chat starts. */
  privs: (JsonWebKey | null)[];
  maxUses: number; // 0 = as many as allowed
  createdAt: number;
}

export interface StoredRoom {
  id: string;
  role: Role;
  master: string;
  createdAt: number;
  /** The link this room came from (its id, not its secret). */
  via?: string;
  /** This side's next message number. */
  sent?: number;
  /** A delete timer has been on at some point, so missing early messages are expected. */
  hadTimer?: boolean;
}

interface Shape {
  invites: StoredInvite[];
  rooms: StoredRoom[];
}

export function loadChats(): Shape {
  try {
    const raw = JSON.parse(localStorage.getItem(STORE) || "{}") as Partial<Shape>;
    return { invites: raw.invites ?? [], rooms: raw.rooms ?? [] };
  } catch {
    return { invites: [], rooms: [] };
  }
}

/** Returns false if the browser refused to store (private window, storage blocked). */
function save(s: Shape): boolean {
  try {
    localStorage.setItem(STORE, JSON.stringify(s));
    return true;
  } catch {
    return false;
  }
}

export function update(fn: (s: Shape) => void): boolean {
  const s = loadChats();
  fn(s);
  return save(s);
}

export const addInvite = (i: StoredInvite) => update((s) => void s.invites.unshift(i));
/** Erases the creator's private key for one use of a link: that chat can no longer be re-derived. */
export const eraseInviteKey = (id: string, slot: number) =>
  update((s) => {
    const i = s.invites.find((x) => x.id === id);
    if (i && Array.isArray(i.privs)) i.privs[slot] = null;
  });
export const dropInvite = (id: string) =>
  update((s) => void (s.invites = s.invites.filter((i) => i.id !== id)));

export function addRoom(r: StoredRoom): boolean {
  return update((s) => {
    if (!s.rooms.some((x) => x.id === r.id)) s.rooms.unshift(r);
  });
}
export const dropRoom = (id: string) => update((s) => void (s.rooms = s.rooms.filter((r) => r.id !== id)));
export const patchRoom = (id: string, patch: Partial<StoredRoom>) =>
  update((s) => {
    const r = s.rooms.find((x) => x.id === id);
    if (r) Object.assign(r, patch);
  });
export const findRoom = (id: string) => loadChats().rooms.find((r) => r.id === id) ?? null;

/** Text that carries one chat to another browser or device. Treat it like a password. */
export function exportAccess(r: StoredRoom): string {
  return (
    ACCESS_PREFIX +
    toB64u(new TextEncoder().encode(JSON.stringify({ id: r.id, role: r.role, master: r.master, createdAt: r.createdAt })))
  );
}

export function importAccess(text: string): StoredRoom {
  const t = text.trim();
  if (!t.startsWith(ACCESS_PREFIX)) throw new Error("That is not a Zesuro chat key");
  let p: Partial<StoredRoom>;
  try {
    p = JSON.parse(new TextDecoder().decode(fromB64u(t.slice(ACCESS_PREFIX.length)))) as Partial<StoredRoom>;
  } catch {
    throw new Error("That chat key is damaged");
  }
  if (
    typeof p.id !== "string" ||
    !/^[0-9a-f-]{36}$/.test(p.id) ||
    (p.role !== "a" && p.role !== "b") ||
    typeof p.master !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(p.master)
  )
    throw new Error("That chat key is incomplete");
  return { id: p.id, role: p.role, master: p.master, createdAt: Number(p.createdAt) || Date.now() };
}

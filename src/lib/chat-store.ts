// Browser only. Private chats this browser takes part in, and everything needed to carry on with them.
// Nothing here is ever sent to the site. Three things shape it:
//
//  - Session-only chats. A chat (or a link you made) marked `mem` lives in the tab's session storage, not in the
//    browser's permanent storage. Close the tab and it is gone.
//  - A passcode (optional). With one set, everything kept here is locked with a key made from the passcode. The key
//    exists only in memory while the chats are unlocked, and the chats lock again by themselves after a while.
//  - Each chat's ratchet state and its history live in their own entry (see lib/chat-session.ts).

import { bytes, fromB64u, toB64u, type Message, type Role } from "./chat-crypto";
import type { RatchetState } from "./chat-ratchet";

const enc = new TextEncoder();
const dec = new TextDecoder();

/** A link this browser made that can still be opened by someone. */
export interface StoredInvite {
  secret: string;
  id: string;
  ownerSecret: string;
  /** One private key per use of the link. A slot is erased (null) as soon as its chat starts. */
  privs: (JsonWebKey | null)[];
  maxUses: number; // 0 = as many as allowed
  createdAt: number;
  /** Kept only until this tab is closed. */
  mem?: boolean;
}

export interface StoredRoom {
  id: string;
  role: Role;
  master: string;
  createdAt: number;
  /** The link this room came from (its id, not its secret). */
  via?: string;
  /** 2 = forward secrecy. Missing: made by an older version, which can't be opened any more. */
  v?: 2;
  /** Kept only until this tab is closed. */
  mem?: boolean;
  /** A delete timer has been on at some point, so missing early messages are expected. */
  hadTimer?: boolean;
}

/** One line of a chat's history, kept here because a message can only be opened once. */
export interface StoredItem {
  id: number;
  at: number;
  msg: Message | null;
  own?: boolean;
}

export interface RoomState {
  v: 2;
  ratchet: RatchetState;
  /** The last server message number dealt with. */
  cursor: number;
  /** Server numbers of messages this side sent, so they are not mistaken for incoming ones. */
  own: number[];
  items: StoredItem[];
}

interface Shape {
  invites: StoredInvite[];
  rooms: StoredRoom[];
}

export interface KV {
  getItem(k: string): string | null;
  setItem(k: string, v: string): void;
  removeItem(k: string): void;
  keys(): string[];
}

export const INDEX = "whenisaid.chats.v1";
export const SESSION_INDEX = "whenisaid.chats.session";
export const STATE_PREFIX = "whenisaid.chatstate.v1.";
export const LOCK_KEY = "whenisaid.chatlock.v1";
export const MODE_KEY = "whenisaid.chatmode.v1";
export const KDF_ITERATIONS = 600_000;

interface LockConfig {
  v: 1;
  salt: string;
  iter: number;
  /** A known text locked with the key: opens only with the right passcode. */
  check: string;
  /** Lock again after this many idle minutes. */
  minutes: number;
}
interface Envelope {
  e: 1;
  iv: string;
  ct: string;
}

const isEnvelope = (raw: string): boolean => raw.startsWith('{"e":1,');

export function createChatStore(local: KV, session: KV) {
  let lock: LockConfig | null = null;
  let key: CryptoKey | null = null;
  let persistent: Shape = { invites: [], rooms: [] };
  let temp: Shape = { invites: [], rooms: [] };
  let queue: Promise<unknown> = Promise.resolve();
  const listeners = new Set<() => void>();
  const emit = () => listeners.forEach((f) => f());
  const enqueue = (fn: () => Promise<unknown>) => (queue = queue.then(fn, fn).catch(() => {}));

  // ---------- locking ----------
  async function encrypt(k: CryptoKey, name: string, text: string): Promise<string> {
    const iv = crypto.getRandomValues(bytes(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(name) }, k, enc.encode(text));
    return JSON.stringify({ e: 1, iv: toB64u(iv), ct: toB64u(ct) } satisfies Envelope);
  }
  async function decrypt(k: CryptoKey, name: string, raw: string): Promise<string | null> {
    try {
      const o = JSON.parse(raw) as Envelope;
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromB64u(o.iv), additionalData: enc.encode(name) },
        k,
        fromB64u(o.ct),
      );
      return dec.decode(plain);
    } catch {
      return null;
    }
  }
  async function derive(pass: string, salt: string, iter: number): Promise<CryptoKey> {
    const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: fromB64u(salt), iterations: iter, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  // ---------- reading and writing the indexes ----------
  const parseShape = (raw: string | null): Shape => {
    try {
      const o = JSON.parse(raw || "{}") as Partial<Shape>;
      return { invites: o.invites ?? [], rooms: o.rooms ?? [] };
    } catch {
      return { invites: [], rooms: [] };
    }
  };
  const nameOf = (kv: KV) => (kv === local ? INDEX : SESSION_INDEX);

  /** Writes one index. Without a passcode this is immediate and reports failure; with one it is queued. */
  function putIndex(kv: KV, shape: Shape): boolean {
    const json = JSON.stringify(shape);
    const name = nameOf(kv);
    if (!lock) {
      try {
        kv.setItem(name, json);
        return true;
      } catch {
        return false;
      }
    }
    const k = key;
    if (!k) return false;
    enqueue(async () => {
      try {
        kv.setItem(name, await encrypt(k, name, json));
      } catch {
        /* storage refused */
      }
    });
    return true;
  }

  async function loadIndexes(): Promise<void> {
    for (const kv of [local, session]) {
      const raw = kv.getItem(nameOf(kv));
      let json: string | null = raw;
      if (raw && isEnvelope(raw)) json = key ? await decrypt(key, nameOf(kv), raw) : null;
      const shape = parseShape(json);
      if (kv === local) persistent = shape;
      else temp = shape;
    }
  }

  function init() {
    try {
      lock = JSON.parse(local.getItem(LOCK_KEY) || "null") as LockConfig | null;
    } catch {
      lock = null;
    }
    if (lock && !lock.salt) lock = null;
    key = null;
    persistent = { invites: [], rooms: [] };
    temp = { invites: [], rooms: [] };
    if (!lock) {
      persistent = parseShape(local.getItem(INDEX));
      temp = parseShape(session.getItem(SESSION_INDEX));
    }
  }
  init();

  const tag = <T extends { mem?: boolean }>(x: T, mem: boolean): T => (mem ? { ...x, mem: true } : x);

  // ---------- the chats and links ----------
  function loadChats(): Shape & { locked: boolean } {
    return {
      invites: [...persistent.invites, ...temp.invites.map((i) => tag(i, true))],
      rooms: [...persistent.rooms, ...temp.rooms.map((r) => tag(r, true))],
      locked: isLocked(),
    };
  }

  /** Returns false if the browser refused to store (private window, storage blocked) or the chats are locked. */
  function update(fn: (s: Shape) => void): boolean {
    if (isLocked()) return false;
    const s = loadChats();
    fn(s);
    const strip = <T extends { mem?: boolean }>(x: T): T => {
      const { mem: _m, ...rest } = x;
      void _m;
      return rest as T;
    };
    persistent = { invites: s.invites.filter((i) => !i.mem), rooms: s.rooms.filter((r) => !r.mem) };
    temp = { invites: s.invites.filter((i) => i.mem).map(strip), rooms: s.rooms.filter((r) => r.mem).map(strip) };
    const a = putIndex(local, persistent);
    const b = temp.invites.length || temp.rooms.length || session.getItem(SESSION_INDEX) ? putIndex(session, temp) : true;
    return a && b;
  }

  const addInvite = (i: StoredInvite) => update((s) => void s.invites.unshift(i));
  /** Erases the creator's private key for one use of a link: that chat can no longer be re-derived. */
  const eraseInviteKey = (id: string, slot: number) =>
    update((s) => {
      const i = s.invites.find((x) => x.id === id);
      if (i && Array.isArray(i.privs)) i.privs[slot] = null;
    });
  const dropInvite = (id: string) => update((s) => void (s.invites = s.invites.filter((i) => i.id !== id)));
  function addRoom(r: StoredRoom): boolean {
    return update((s) => {
      if (!s.rooms.some((x) => x.id === r.id)) s.rooms.unshift(r);
    });
  }
  /** Forgets the chat and everything kept for it. */
  function dropRoom(id: string): boolean {
    for (const kv of [local, session]) {
      try {
        kv.removeItem(STATE_PREFIX + id);
      } catch {
        /* nothing there */
      }
    }
    return update((s) => void (s.rooms = s.rooms.filter((r) => r.id !== id)));
  }
  const patchRoom = (id: string, patch: Partial<StoredRoom>) =>
    update((s) => {
      const r = s.rooms.find((x) => x.id === id);
      if (r) Object.assign(r, patch);
    });
  const findRoom = (id: string) => loadChats().rooms.find((r) => r.id === id) ?? null;

  // ---------- each chat's own state ----------
  async function loadRoomState(id: string, mem: boolean): Promise<RoomState | null> {
    if (isLocked()) return null;
    const kv = mem ? session : local;
    const raw = kv.getItem(STATE_PREFIX + id);
    if (!raw) return null;
    let json: string | null = raw;
    if (isEnvelope(raw)) json = key ? await decrypt(key, STATE_PREFIX + id, raw) : null;
    if (!json) return null;
    try {
      const s = JSON.parse(json) as RoomState;
      return s && s.v === 2 && s.ratchet ? s : null;
    } catch {
      return null;
    }
  }
  async function saveRoomState(id: string, mem: boolean, st: RoomState): Promise<boolean> {
    if (isLocked()) return false;
    const kv = mem ? session : local;
    const name = STATE_PREFIX + id;
    const json = JSON.stringify(st);
    try {
      kv.setItem(name, lock && key ? await encrypt(key, name, json) : json);
      return true;
    } catch {
      return false;
    }
  }

  // ---------- passcode ----------
  const isLocked = () => !!lock && !key;
  const lockConfigured = () => !!lock;
  const autoLockMinutes = () => lock?.minutes ?? 0;

  async function everyEntry(): Promise<{ kv: KV; name: string }[]> {
    const out: { kv: KV; name: string }[] = [];
    for (const kv of [local, session]) {
      out.push({ kv, name: nameOf(kv) });
      for (const k of kv.keys()) if (k.startsWith(STATE_PREFIX)) out.push({ kv, name: k });
    }
    return out;
  }

  /** Locks everything with a passcode (or changes it). Needs the chats to be unlocked now. */
  async function setPasscode(pass: string, minutes: number, iter = KDF_ITERATIONS): Promise<boolean> {
    if (isLocked() || pass.length < 8) return false;
    const salt = toB64u(crypto.getRandomValues(bytes(16)));
    const next = await derive(pass, salt, iter);
    // Read everything first, so a failure part-way leaves what is stored exactly as it was.
    const found: { kv: KV; name: string; plain: string }[] = [];
    for (const { kv, name } of await everyEntry()) {
      const raw = kv.getItem(name);
      if (!raw) continue;
      const plain = isEnvelope(raw) ? (key ? await decrypt(key, name, raw) : null) : raw;
      if (plain === null) return false;
      found.push({ kv, name, plain });
    }
    for (const f of found) f.kv.setItem(f.name, await encrypt(next, f.name, f.plain));
    const cfg: LockConfig = { v: 1, salt, iter, check: await encrypt(next, "lockcheck", "zesuro-chat-lock"), minutes };
    local.setItem(LOCK_KEY, JSON.stringify(cfg));
    lock = cfg;
    key = next;
    // An index that did not exist yet is still written under the new key.
    putIndex(local, persistent);
    emit();
    return true;
  }

  async function checkPasscode(pass: string): Promise<CryptoKey | null> {
    if (!lock) return null;
    try {
      const k = await derive(pass, lock.salt, lock.iter);
      return (await decrypt(k, "lockcheck", lock.check)) === "zesuro-chat-lock" ? k : null;
    } catch {
      return null;
    }
  }

  async function unlock(pass: string): Promise<boolean> {
    const k = await checkPasscode(pass);
    if (!k) return false;
    key = k;
    await loadIndexes();
    emit();
    return true;
  }

  /** Forgets the key and everything decrypted. The chats are unreadable until the passcode is entered again. */
  function lockNow() {
    if (!lock) return;
    key = null;
    persistent = { invites: [], rooms: [] };
    temp = { invites: [], rooms: [] };
    emit();
  }

  /** Removes the passcode: everything is stored plainly again. Needs the passcode. */
  async function removePasscode(pass: string): Promise<boolean> {
    const k = await checkPasscode(pass);
    if (!k || !lock) return false;
    const found: { kv: KV; name: string; plain: string }[] = [];
    for (const { kv, name } of await everyEntry()) {
      const raw = kv.getItem(name);
      if (!raw || !isEnvelope(raw)) continue;
      const plain = await decrypt(k, name, raw);
      if (plain === null) return false;
      found.push({ kv, name, plain });
    }
    for (const f of found) f.kv.setItem(f.name, f.plain);
    local.removeItem(LOCK_KEY);
    lock = null;
    key = null;
    await queue;
    init();
    emit();
    return true;
  }

  function setAutoLockMinutes(minutes: number) {
    if (!lock) return;
    lock = { ...lock, minutes };
    local.setItem(LOCK_KEY, JSON.stringify(lock));
  }

  // ---------- keeping chats only for this tab ----------
  const keepMode = (): "device" | "session" => (local.getItem(MODE_KEY) === "session" ? "session" : "device");
  const setKeepMode = (m: "device" | "session") => {
    try {
      local.setItem(MODE_KEY, m);
    } catch {
      /* not stored: the default applies */
    }
  };

  // ---------- erasing ----------
  /** Removes every chat, link and chat state from this browser. The passcode setting itself stays. */
  function wipeChats() {
    for (const kv of [local, session]) {
      for (const k of kv.keys())
        if (k.startsWith("whenisaid.chat") && k !== LOCK_KEY && k !== MODE_KEY) {
          try {
            kv.removeItem(k);
          } catch {
            /* gone already */
          }
        }
    }
    persistent = { invites: [], rooms: [] };
    temp = { invites: [], rooms: [] };
    emit();
  }

  /** Erases every chat AND the passcode setting: for someone who has forgotten the passcode. */
  function eraseEverything() {
    wipeChats();
    try {
      local.removeItem(LOCK_KEY);
    } catch {
      /* gone already */
    }
    init();
    emit();
  }

  return {
    eraseEverything,
    loadChats, update, addInvite, eraseInviteKey, dropInvite, addRoom, dropRoom, patchRoom, findRoom,
    loadRoomState, saveRoomState,
    isLocked, lockConfigured, autoLockMinutes, setPasscode, unlock, lockNow, removePasscode, setAutoLockMinutes,
    keepMode, setKeepMode, wipeChats,
    subscribe: (f: () => void) => {
      listeners.add(f);
      return () => void listeners.delete(f);
    },
    flush: () => queue,
    /** Re-reads everything from storage (used after storage was cleared elsewhere). */
    reload: () => {
      init();
      emit();
    },
  };
}

// ---------- the browser's own store ----------
const kvOf = (s: () => Storage): KV => ({
  getItem: (k) => s().getItem(k),
  setItem: (k, v) => s().setItem(k, v),
  removeItem: (k) => s().removeItem(k),
  keys: () => {
    const st = s();
    const out: string[] = [];
    for (let i = 0; i < st.length; i++) {
      const k = st.key(i);
      if (k) out.push(k);
    }
    return out;
  },
});

let instance: ReturnType<typeof createChatStore> | null = null;
export function chatStore() {
  if (!instance) instance = createChatStore(kvOf(() => localStorage), kvOf(() => sessionStorage));
  return instance;
}

export const loadChats = () => chatStore().loadChats();
export const update = (fn: (s: Shape) => void) => chatStore().update(fn);
export const addInvite = (i: StoredInvite) => chatStore().addInvite(i);
export const eraseInviteKey = (id: string, slot: number) => chatStore().eraseInviteKey(id, slot);
export const dropInvite = (id: string) => chatStore().dropInvite(id);
export const addRoom = (r: StoredRoom) => chatStore().addRoom(r);
export const dropRoom = (id: string) => chatStore().dropRoom(id);
export const patchRoom = (id: string, patch: Partial<StoredRoom>) => chatStore().patchRoom(id, patch);
export const findRoom = (id: string) => chatStore().findRoom(id);
export const loadRoomState = (id: string, mem: boolean) => chatStore().loadRoomState(id, mem);
export const saveRoomState = (id: string, mem: boolean, st: RoomState) => chatStore().saveRoomState(id, mem, st);

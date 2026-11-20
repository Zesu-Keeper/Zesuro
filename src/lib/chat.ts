import { createHash, timingSafeEqual } from "node:crypto";
import { getDb } from "./db";
import { EntryError } from "./errors";
import { HEX64, UUID } from "./opening";

// Private chats, server side. Everything stored here is opaque to the server:
//   - an invite's id is a hash of the link's secret (the secret itself stays after the "#");
//   - "hello" and "join" are the two halves of a key exchange, encrypted with a key derived
//     from that secret;
//   - messages are encrypted and padded in the browser.
// The server's only jobs are to count how many times a link has been used, to hand blobs to
// whoever proves they hold a room's key, and to delete on request or on a timer.

const B64U = /^[A-Za-z0-9_-]+$/;
const MAX_JOIN = 4_000; // includes the opener's post-quantum public key
const MAX_HELLO = 16_000; // one public key per allowed use of the link
const MAX_BLOB = 46_000; // 32 KiB padded plaintext + IV + tag, base64url
const MAX_MESSAGES = 2_000; // per room
const MAX_ROOM_BYTES = 8_000_000; // per room
const MAX_TOTAL_BYTES = 400_000_000; // all chats together: the disk is small
/** A link opens at most this many chats ("unlimited" means this many). */
export const MAX_ROOMS_PER_INVITE = 100;
const DAY = 86_400_000;
export const TTL_CHOICES = [0, 86_400_000, 7 * 86_400_000, 30 * 86_400_000];
const PAGE = 200;

let totalBytes = -1;
let totalAt = 0;
/** Total size of stored messages, cached for a minute and bumped on every write. */
function chatBytes(now: number): number {
  if (totalBytes < 0 || now - totalAt > 60_000) {
    const r = getDb().prepare("SELECT COALESCE(SUM(length(blob)), 0) AS n FROM chat_messages").get() as { n: number };
    totalBytes = Number(r.n);
    totalAt = now;
  }
  return totalBytes;
}

const sha = (s: string) => createHash("sha256").update(s).digest();
const blobOk = (v: unknown, max: number): v is string =>
  typeof v === "string" && v.length >= 20 && v.length <= max && B64U.test(v);

function sameHash(secret: unknown, storedHex: string): boolean {
  if (typeof secret !== "string" || !HEX64.test(secret)) return false;
  const want = Buffer.from(storedHex, "hex");
  return want.length === 32 && timingSafeEqual(sha(secret), want);
}

interface InviteRow {
  id: string;
  owner_hash: string;
  hello: string;
  max_uses: number;
  uses: number;
  closed: number;
  created_at: number;
}
interface RoomRow {
  id: string;
  invite_id: string;
  auth_hash: string;
  join_blob: string;
  ttl_ms: number;
  created_at: number;
  deleted_at: number | null;
}

const isOpen = (i: InviteRow) =>
  !i.closed && Number(i.uses) < (Number(i.max_uses) === 0 ? MAX_ROOMS_PER_INVITE : Number(i.max_uses));

export function createInvite(input: Record<string, unknown>): { id: string } {
  const { id, owner, hello, maxUses } = input;
  if (typeof id !== "string" || !HEX64.test(id)) throw new EntryError("Invalid link");
  if (typeof owner !== "string" || !HEX64.test(owner)) throw new EntryError("Invalid link");
  if (!blobOk(hello, MAX_HELLO)) throw new EntryError("Invalid link");
  if (typeof maxUses !== "number" || !Number.isInteger(maxUses) || maxUses < 0 || maxUses > MAX_ROOMS_PER_INVITE)
    throw new EntryError("Choose how many times the link can be used");
  const res = getDb()
    .prepare(
      "INSERT OR IGNORE INTO chat_invites (id, owner_hash, hello, max_uses, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .run(id, owner, hello, maxUses, Date.now());
  if (Number(res.changes) === 0) throw new EntryError("That link already exists", 409);
  return { id };
}

function invite(id: string): InviteRow {
  const row = HEX64.test(id)
    ? (getDb().prepare("SELECT * FROM chat_invites WHERE id = ?").get(id) as unknown as InviteRow | undefined)
    : undefined;
  if (!row) throw new EntryError("This link is not valid", 404);
  return row;
}

const capacity = (i: InviteRow) => (Number(i.max_uses) === 0 ? MAX_ROOMS_PER_INVITE : Number(i.max_uses));

/** What someone opening the link needs: the creator's public keys, and which one to use. */
export function inviteHello(id: string): { hello: string; open: boolean; slot: number } {
  const i = invite(id);
  const taken = new Set(
    (getDb().prepare("SELECT slot FROM chat_rooms WHERE invite_id = ? AND slot IS NOT NULL").all(id) as unknown as { slot: number }[]).map((r) => Number(r.slot)),
  );
  let slot = 0;
  while (taken.has(slot)) slot++;
  return { hello: i.hello, open: isOpen(i) && slot < capacity(i), slot };
}

function ownedInvite(id: string, ownerSecret: unknown): InviteRow {
  const i = invite(id);
  if (!sameHash(ownerSecret, i.owner_hash)) throw new EntryError("This link is not valid", 404);
  return i;
}

/** For the link's creator: who has joined. */
export function inviteStatus(id: string, ownerSecret: unknown) {
  const i = ownedInvite(id, ownerSecret);
  const rooms = getDb()
    .prepare(
      "SELECT id, join_blob, created_at, deleted_at, slot FROM chat_rooms WHERE invite_id = ? AND slot IS NOT NULL ORDER BY slot LIMIT ?",
    )
    .all(id, MAX_ROOMS_PER_INVITE) as unknown as RoomRow[];
  return {
    maxUses: Number(i.max_uses),
    uses: Number(i.uses),
    open: isOpen(i),
    rooms: rooms.map((r) => ({
      id: r.id,
      join: r.join_blob,
      slot: Number((r as unknown as { slot: number }).slot),
      createdAt: Number(r.created_at),
      deleted: r.deleted_at !== null,
    })),
  };
}

/** The creator cancels the link: nobody else can join. Existing chats carry on. */
export function closeInvite(id: string, ownerSecret: unknown): void {
  ownedInvite(id, ownerSecret);
  getDb().prepare("UPDATE chat_invites SET closed = 1 WHERE id = ?").run(id);
}

/** Uses up one opening of the link and creates that person's own room. */
export function joinInvite(id: string, input: Record<string, unknown>): { room: string } {
  const { room, join, auth, slot } = input;
  if (typeof room !== "string" || !UUID.test(room)) throw new EntryError("Invalid request");
  if (!blobOk(join, MAX_JOIN)) throw new EntryError("Invalid request");
  if (typeof slot !== "number" || !Number.isInteger(slot) || slot < 0 || slot >= MAX_ROOMS_PER_INVITE)
    throw new EntryError("Invalid request");
  if (typeof auth !== "string" || !HEX64.test(auth)) throw new EntryError("Invalid request");
  const db = getDb();
  db.exec("BEGIN IMMEDIATE");
  try {
    const i = invite(id);
    if (slot >= capacity(i)) throw new EntryError("Invalid request");
    if (!isOpen(i))
      throw new EntryError(
        i.closed ? "This link has been cancelled." : "This link has already been used.",
        410,
      );
    if (db.prepare("SELECT 1 FROM chat_rooms WHERE invite_id = ? AND slot = ?").get(id, slot))
      throw new EntryError("Someone opened the link at the same moment. Try again.", 409);
    db.prepare(
      "INSERT INTO chat_rooms (id, invite_id, auth_hash, join_blob, created_at, slot) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(room, id, auth, join, Date.now(), slot);
    db.prepare("UPDATE chat_invites SET uses = uses + 1 WHERE id = ?").run(id);
    db.exec("COMMIT");
    return { room };
  } catch (e) {
    db.exec("ROLLBACK");
    if (e instanceof EntryError) throw e;
    throw new EntryError("Invalid request", 409); // e.g. room id already taken
  }
}

function room(id: string, token: unknown): RoomRow {
  const row = UUID.test(id)
    ? (getDb().prepare("SELECT * FROM chat_rooms WHERE id = ?").get(id) as unknown as RoomRow | undefined)
    : undefined;
  // Same answer for "no such chat" and "wrong key", so ids can't be probed.
  if (!row || !sameHash(token, row.auth_hash)) throw new EntryError("Chat not found", 404);
  if (row.deleted_at !== null) throw new EntryError("This chat has been deleted.", 410);
  return row;
}

function purge(r: RoomRow, now: number): void {
  if (Number(r.ttl_ms) > 0)
    getDb()
      .prepare("DELETE FROM chat_messages WHERE room_id = ? AND created_at < ?")
      .run(r.id, now - Number(r.ttl_ms));
}

let lastSweep = 0;
/** Housekeeping, run now and then as the site is used. Timers also run for chats nobody has open. */
function sweep(now: number): void {
  if (now - lastSweep < 600_000) return;
  lastSweep = now;
  const db = getDb();
  db.prepare(
    `DELETE FROM chat_messages WHERE id IN (
       SELECT m.id FROM chat_messages m JOIN chat_rooms r ON r.id = m.room_id
        WHERE r.ttl_ms > 0 AND m.created_at < ? - r.ttl_ms)`,
  ).run(now);
  // Chats nobody wrote in for a long time, and chats opened but never used, are cleared.
  const idle = db
    .prepare(
      `SELECT r.id FROM chat_rooms r
        WHERE r.deleted_at IS NULL
          AND COALESCE((SELECT MAX(created_at) FROM chat_messages WHERE room_id = r.id), r.created_at) < ?`,
    )
    .all(now - 90 * DAY) as unknown as { id: string }[];
  for (const r of idle) tombstone(r.id, now);
  // Links never opened, and old links of any kind, go. Their chats no longer point back at them.
  db.prepare("DELETE FROM chat_invites WHERE created_at < ? AND (uses = 0 OR closed = 1 OR uses >= CASE max_uses WHEN 0 THEN ? ELSE max_uses END)")
    .run(now - 30 * DAY, MAX_ROOMS_PER_INVITE);
  // Deleted chats leave a bare marker for a month (so the other side learns it was deleted).
  db.prepare("DELETE FROM chat_rooms WHERE deleted_at IS NOT NULL AND deleted_at < ?").run(now - 30 * DAY);
  totalBytes = -1;
}

/** Removes a chat's messages and everything that says who it came from or when. */
function tombstone(id: string, now: number): void {
  const db = getDb();
  db.prepare("DELETE FROM chat_messages WHERE room_id = ?").run(id);
  db.prepare(
    "UPDATE chat_rooms SET deleted_at = ?, join_blob = '', invite_id = '', slot = NULL, created_at = 0 WHERE id = ?",
  ).run(now, id);
}

export function readRoom(id: string, token: unknown, after: number) {
  const now = Date.now();
  sweep(now);
  const r = room(id, token);
  purge(r, now);
  const rows = getDb()
    .prepare("SELECT id, blob, created_at FROM chat_messages WHERE room_id = ? AND id > ? ORDER BY id LIMIT ?")
    .all(id, Number.isSafeInteger(after) && after > 0 ? after : 0, PAGE + 1) as unknown as {
    id: number;
    blob: string;
    created_at: number;
  }[];
  return {
    ttl: Number(r.ttl_ms),
    more: rows.length > PAGE,
    messages: rows.slice(0, PAGE).map((m) => ({ id: Number(m.id), blob: m.blob, at: Number(m.created_at) })),
  };
}

export function postMessage(id: string, token: unknown, blob: unknown): { id: number; at: number } {
  const now = Date.now();
  const r = room(id, token);
  if (!blobOk(blob, MAX_BLOB)) throw new EntryError("That message is too long");
  purge(r, now);
  const db = getDb();
  const n = db
    .prepare("SELECT COUNT(*) AS n, COALESCE(SUM(length(blob)), 0) AS b FROM chat_messages WHERE room_id = ?")
    .get(id) as { n: number; b: number };
  if (Number(n.n) >= MAX_MESSAGES || Number(n.b) >= MAX_ROOM_BYTES)
    throw new EntryError("This chat is full. Delete some of it or start a new one.", 409);
  if (chatBytes(now) >= MAX_TOTAL_BYTES)
    throw new EntryError("The site can't take more chat messages right now. Try again later.", 503);
  totalBytes += blob.length;
  const res = db
    .prepare("INSERT INTO chat_messages (room_id, blob, created_at) VALUES (?, ?, ?)")
    .run(id, blob, now);
  return { id: Number(res.lastInsertRowid), at: now };
}

/** Either side can set the auto-delete timer. 0 turns it off. */
export function setRoomTtl(id: string, token: unknown, ttl: unknown): { ttl: number } {
  const r = room(id, token);
  if (typeof ttl !== "number" || !TTL_CHOICES.includes(ttl)) throw new EntryError("Invalid timer");
  getDb().prepare("UPDATE chat_rooms SET ttl_ms = ? WHERE id = ?").run(ttl, id);
  purge({ ...r, ttl_ms: ttl }, Date.now());
  return { ttl };
}

/** Either side can delete the chat: every message goes, for both, and so does its history. */
export function deleteRoom(id: string, token: unknown): void {
  room(id, token);
  const db = getDb();
  db.exec("BEGIN IMMEDIATE");
  try {
    tombstone(id, Date.now());
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
  totalBytes = -1;
  // Overwrite what was just deleted in the write-ahead log too, not just in the main file.
  try {
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  } catch {
    /* busy: the next checkpoint will do it */
  }
}

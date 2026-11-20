// Private replies on the server (the locking itself is in lib/mailbox.ts). The site stores locked replies it can't
// read. Anyone may fetch all of them: authors find theirs by trying their own keys, so fetching tells the site
// nothing about who wrote which post (and every visitor's browser fetches the same thing, see InboxCover).

import { getDb } from "./db";
import { EntryError } from "./errors";
import { parseMailboxLeaves, type MailboxLeaf } from "./mailbox";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_BLOB = 12_000;
const KEEP_MS = 30 * 86_400_000;
const PER_POST = 500;
const PAGE = 200;

export function getMailbox(uid: string): { root: string; leaves: MailboxLeaf[]; createdAt: number } | null {
  if (!UUID.test(uid)) return null;
  const r = getDb()
    .prepare("SELECT e.mailbox_root AS root, e.created_at AS at, m.leaves AS leaves FROM entries e JOIN mailboxes m ON m.uid = e.uid WHERE e.uid = ?")
    .get(uid) as { root: string | null; at: number; leaves: string } | undefined;
  if (!r || !r.root) return null;
  const leaves = parseMailboxLeaves(JSON.parse(r.leaves));
  return leaves ? { root: r.root, leaves, createdAt: Number(r.at) } : null;
}

export function postReply(uid: string, blob: unknown): { id: number } {
  if (!getMailbox(uid)) throw new EntryError("This post doesn't take private replies", 404);
  if (typeof blob !== "string" || blob.length > MAX_BLOB || !/^[A-Za-z0-9_-]+$/.test(blob)) throw new EntryError("That reply is not valid");
  const db = getDb();
  const n = db.prepare("SELECT COUNT(*) AS n FROM mailbox_messages WHERE entry_uid = ?").get(uid) as { n: number };
  if (Number(n.n) >= PER_POST) throw new EntryError("This post has had too many private replies. Try again later.", 429);
  const res = db.prepare("INSERT INTO mailbox_messages (entry_uid, blob, created_at) VALUES (?, ?, ?)").run(uid, blob, Date.now());
  return { id: Number(res.lastInsertRowid) };
}

/** Every locked reply newer than `after`, oldest first. Replies older than 30 days are deleted. */
export function readInbox(after: number) {
  const db = getDb();
  db.prepare("DELETE FROM mailbox_messages WHERE created_at < ?").run(Date.now() - KEEP_MS);
  const rows = db
    .prepare("SELECT id, entry_uid, blob, created_at FROM mailbox_messages WHERE id > ? ORDER BY id LIMIT ?")
    .all(Math.max(0, Math.floor(after) || 0), PAGE + 1) as unknown as { id: number; entry_uid: string; blob: string; created_at: number }[];
  return {
    more: rows.length > PAGE,
    messages: rows.slice(0, PAGE).map((r) => ({ id: Number(r.id), uid: r.entry_uid, blob: r.blob, at: Number(r.created_at) })),
  };
}

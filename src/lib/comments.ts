import { getDb } from "./db";
import { EntryError } from "./errors";
import { assertRecordWritable } from "./writer";
import { UUID, sha256Hex } from "./opening";
import {
  blockedDomainIn,
  countLinks,
  DUP_ENTRIES,
  DUP_WINDOW_MS,
  dupHash,
  MAX_LINKS_COMMENT,
} from "./spam";
import { hasHiddenControls } from "./text";

// Comments are permanent and have their own hash chain, so the time a follow-up was posted
// is as checkable as the time an entry was sealed.
//
// The chain covers a fingerprint of each comment's text (SHA-256), not the text itself. That
// lets machine-confirmed spam have its text removed while every hash still verifies, and
// anyone who kept the original words can still prove what a removed comment said. Reports
// from readers only ever collapse a comment; they never remove it.
//
// Every comment carries a fixed-size `tag`. Ordinary comments fill it with random bytes. An
// author's follow-up fills it with an encrypted signature that only holders of that entry's
// private link can open and check. To everyone else, the server included, the two look the
// same, so an author's follow-ups can't be picked out.

export const MAX_COMMENT = 2000;
/** 12-byte AES-GCM IV + 64-byte Ed25519 signature + 16-byte GCM tag. */
export const TAG_BYTES = 92;
const TAG_RE = /^[A-Za-z0-9_-]{123}$/;
const VOTER = /^[0-9a-f]{64}$/;
const GENESIS = "0".repeat(64);
export const COMMENT_PAGE = 50;
/** Repeat-text rules only apply to comments at least this long ("Agreed" may repeat freely). */
const DUP_MIN_CHARS = 25;

export interface PublicComment {
  id: number;
  uid: string;
  entryUid: string;
  /** Empty once removed. */
  text: string;
  /** SHA-256 of the text as posted. Stays after removal. */
  textHash: string;
  tag: string;
  createdAt: number;
  prevHash: string;
  commentHash: string;
  reports: number;
  /** Text removed as machine-confirmed spam. */
  removed: boolean;
  removedReason: string | null;
}

interface CommentRow {
  id: number;
  uid: string;
  entry_uid: string;
  text: string;
  text_hash: string;
  tag: string;
  created_at: number;
  prev_hash: string;
  comment_hash: string;
  reports: number;
  removed_at: number | null;
  removed_reason: string | null;
}

function hashComment(
  prev: string,
  c: { id: number; uid: string; entryUid: string; createdAt: number; textHash: string; tag: string },
): string {
  return sha256Hex(
    JSON.stringify(["c2", prev, c.id, c.uid, c.entryUid, c.createdAt, c.textHash, c.tag]),
  );
}

function toPublic(r: CommentRow): PublicComment {
  const removed = r.removed_at !== null;
  return {
    id: r.id,
    uid: r.uid,
    entryUid: r.entry_uid,
    text: removed ? "" : r.text,
    textHash: r.text_hash,
    tag: r.tag,
    createdAt: r.created_at,
    prevHash: r.prev_hash,
    commentHash: r.comment_hash,
    reports: Number(r.reports),
    removed,
    removedReason: r.removed_reason,
  };
}

function validTag(t: unknown): t is string {
  if (typeof t !== "string" || !TAG_RE.test(t)) return false;
  const b = Buffer.from(t, "base64url");
  // Exactly TAG_BYTES and canonically encoded, so a tag can't carry hidden extra bits.
  return b.length === TAG_BYTES && b.toString("base64url") === t;
}

/**
 * Removes the text of comments (never the record of them). Nothing in the app calls this:
 * no rule and no number of spam flags removes text. It exists for the operator's admin tool.
 */
export function removeCommentText(where: string, params: (string | number)[], reason: string): number {
  const res = getDb()
    .prepare(
      `UPDATE comments SET text = '', removed_at = ?, removed_reason = ?
        WHERE removed_at IS NULL AND (${where})`,
    )
    .run(Date.now(), reason, ...params);
  return Number(res.changes);
}

export function addComment(entryUid: string, input: Record<string, unknown>): PublicComment {
  assertRecordWritable();
  if (!UUID.test(entryUid)) throw new EntryError("Entry not found", 404);
  const uid = input.uid;
  if (typeof uid !== "string" || !UUID.test(uid)) throw new EntryError("Invalid comment id");
  if (typeof input.text !== "string") throw new EntryError("Write something first");
  const text = input.text.replace(/\r\n?/g, "\n").trim();
  if (text.length === 0) throw new EntryError("Write something first");
  if (text.length > MAX_COMMENT)
    throw new EntryError(`Comments can be up to ${MAX_COMMENT.toLocaleString("en")} characters`);
  if (hasHiddenControls(text)) throw new EntryError("That comment contains hidden control characters");
  if (!validTag(input.tag)) throw new EntryError("Invalid comment");
  const tag = input.tag;

  // Door rules: refused posts are never recorded.
  if (countLinks(text) > MAX_LINKS_COMMENT)
    throw new EntryError(`Comments can include up to ${MAX_LINKS_COMMENT} links`);
  if (blockedDomainIn(text)) throw new EntryError("That comment links to a blocked site");

  const now = Date.now();
  const db = getDb();
  const dup = dupHash(text);
  if (text.length >= DUP_MIN_CHARS) {
    const same = db
      .prepare(
        `SELECT entry_uid FROM comments
          WHERE dup_hash = ? AND created_at > ? GROUP BY entry_uid`,
      )
      .all(dup, now - DUP_WINDOW_MS) as { entry_uid: string }[];
    if (same.some((r) => r.entry_uid === entryUid))
      throw new EntryError("That has already been said here");
    if (same.length >= DUP_ENTRIES) {
      // The same words on entry after entry: refuse the new copy. Earlier copies stay.
      throw new EntryError("That text has been posted too many times");
    }
  }

  const textHash = sha256Hex(text);
  db.exec("BEGIN IMMEDIATE");
  try {
    if (!db.prepare("SELECT 1 FROM entries WHERE uid = ?").get(entryUid))
      throw new EntryError("Entry not found", 404);
    const last = db
      .prepare("SELECT id, comment_hash, created_at FROM comments ORDER BY id DESC LIMIT 1")
      .get() as { id: number; comment_hash: string; created_at: number } | undefined;
    const id = (last?.id ?? 0) + 1;
    const prev = last?.comment_hash ?? GENESIS;
    // Never let the recorded time run backwards, even if the system clock does.
    const createdAt = Math.max(now, last?.created_at ?? 0);
    const h = hashComment(prev, { id, uid, entryUid, createdAt, textHash, tag });
    db.prepare(
      `INSERT INTO comments
         (id, uid, entry_uid, text, text_hash, dup_hash, tag, created_at, prev_hash, comment_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(id, uid, entryUid, text, textHash, dup, tag, createdAt, prev, h);
    db.prepare("UPDATE entries SET comment_count = comment_count + 1 WHERE uid = ?").run(entryUid);
    db.exec("COMMIT");
    return toPublic({
      id,
      uid,
      entry_uid: entryUid,
      text,
      text_hash: textHash,
      tag,
      created_at: createdAt,
      prev_hash: prev,
      comment_hash: h,
      reports: 0,
      removed_at: null,
      removed_reason: null,
    });
  } catch (e) {
    db.exec("ROLLBACK");
    if (e instanceof Error && /UNIQUE/i.test(e.message))
      throw new EntryError("That comment already exists", 409);
    throw e;
  }
}

/** One spam flag per browser per comment. Flags are counted and shown; nothing is hidden. */
export function reportComment(id: number, token: unknown): { reports: number } {
  if (!Number.isSafeInteger(id) || id < 1) throw new EntryError("Comment not found", 404);
  if (typeof token !== "string" || !VOTER.test(token)) throw new EntryError("Invalid voter");
  const voter = sha256Hex(`whenisaid:voter:v1:${token}`);
  const db = getDb();
  db.exec("BEGIN IMMEDIATE");
  try {
    const c = db.prepare("SELECT removed_at FROM comments WHERE id = ?").get(id) as
      | { removed_at: number | null }
      | undefined;
    if (!c) throw new EntryError("Comment not found", 404);
    if (c.removed_at !== null) throw new EntryError("That comment has already been removed", 409);
    const res = db
      .prepare("INSERT OR IGNORE INTO comment_reports (comment_id, voter, at) VALUES (?, ?, ?)")
      .run(id, voter, Date.now());
    if (Number(res.changes) > 0)
      db.prepare("UPDATE comments SET reports = reports + 1 WHERE id = ?").run(id);
    const r = db.prepare("SELECT reports FROM comments WHERE id = ?").get(id) as { reports: number };
    db.exec("COMMIT");
    return { reports: Number(r.reports) };
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
}

/** Oldest first, a page at a time: pass the last id you have as `after`. */
export function listComments(
  entryUid: string,
  opts: { after?: number; limit?: number } = {},
): { comments: PublicComment[]; more: boolean } {
  if (!UUID.test(entryUid)) return { comments: [], more: false };
  const limit = Math.min(Math.max(Math.floor(opts.limit ?? COMMENT_PAGE), 1), 100);
  const after = Math.max(Math.floor(opts.after ?? 0), 0);
  const rows = getDb()
    .prepare("SELECT * FROM comments WHERE entry_uid = ? AND id > ? ORDER BY id ASC LIMIT ?")
    .all(entryUid, after, limit + 1) as unknown as CommentRow[];
  return { comments: rows.slice(0, limit).map(toPublic), more: rows.length > limit };
}

/** Recomputes the comment chain. Walks in pages so memory stays flat as it grows. */
export function verifyComments(): { ok: boolean; count: number; tip: string; brokenAt?: number } {
  const stmt = getDb().prepare("SELECT * FROM comments WHERE id > ? ORDER BY id ASC LIMIT 1000");
  let prev = GENESIS;
  let count = 0;
  let after = 0;
  for (;;) {
    const rows = stmt.all(after) as unknown as CommentRow[];
    if (rows.length === 0) break;
    for (const r of rows) {
      const h = hashComment(prev, {
        id: r.id,
        uid: r.uid,
        entryUid: r.entry_uid,
        createdAt: r.created_at,
        textHash: r.text_hash,
        tag: r.tag,
      });
      // Text still present must match its fingerprint; removed text must really be gone.
      const textOk = r.removed_at === null ? sha256Hex(r.text) === r.text_hash : r.text === "";
      if (r.prev_hash !== prev || r.comment_hash !== h || !textOk)
        return { ok: false, count, tip: prev, brokenAt: r.id };
      prev = h;
      count++;
      after = r.id;
    }
  }
  return { ok: true, count, tip: prev };
}

/** The comment chain as the hash covers it (the text itself is only represented by its hash). */
export function listCommentLog(afterId: number, limit: number) {
  const rows = getDb()
    .prepare("SELECT * FROM comments WHERE id > ? ORDER BY id ASC LIMIT ?")
    .all(Math.max(0, Math.floor(afterId) || 0), Math.min(Math.max(Math.floor(limit) || 500, 1), 1000)) as unknown as CommentRow[];
  return rows.map((r) => ({
    id: r.id,
    uid: r.uid,
    entryUid: r.entry_uid,
    createdAt: r.created_at,
    textHash: r.text_hash,
    tag: r.tag,
    prevHash: r.prev_hash,
    commentHash: r.comment_hash,
  }));
}

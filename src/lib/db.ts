import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";

// SQLite for the prototype (built into Node 22). Swap for Postgres before launch.
const dir = path.join(process.cwd(), "data");

const g = globalThis as unknown as { __whenisaidDb?: DatabaseSync };

function open(): DatabaseSync {
  fs.mkdirSync(dir, { recursive: true });
  const d = new DatabaseSync(path.join(dir, "whenisaid.db"));
  // Wait for other processes (e.g. Next build workers) instead of failing on a lock.
  d.exec("PRAGMA busy_timeout = 10000;");
  d.exec("PRAGMA journal_mode = WAL;");
  // Deleted rows (e.g. chat messages) are overwritten with zeros, not just unlinked.
  d.exec("PRAGMA secure_delete = ON;");
  d.exec(`
    CREATE TABLE IF NOT EXISTS entries (
      seq          INTEGER PRIMARY KEY,
      uid          TEXT NOT NULL UNIQUE,
      text         TEXT NOT NULL,
      commitment   TEXT NOT NULL,
      nonce        TEXT NOT NULL,
      created_at   INTEGER NOT NULL,
      mode         TEXT NOT NULL,
      reveal_at    INTEGER,
      deadline_at  INTEGER,
      prev_hash    TEXT NOT NULL,
      entry_hash   TEXT NOT NULL,
      reveal_pkg   TEXT,
      revealed_at  INTEGER,
      handle       TEXT
    );
    CREATE INDEX IF NOT EXISTS entries_due ON entries (reveal_at) WHERE revealed_at IS NULL;
  `);
  migrate(d);
  return d;
}

function hasChatColumn(d: DatabaseSync, name: string): boolean {
  const cols = d.prepare("PRAGMA table_info(chat_rooms)").all() as unknown as { name: string }[];
  return cols.some((c) => c.name === name);
}

function hasColumn(d: DatabaseSync, name: string, table: "entries" | "comments" = "entries"): boolean {
  const cols = d.prepare(`PRAGMA table_info(${table})`).all() as unknown as { name: string }[];
  return cols.some((c) => c.name === name);
}

// Additive migrations. Existing rows keep their old behaviour (schedule public, hash v1).
function migrate(d: DatabaseSync): void {
  if (!hasColumn(d, "reveal_public"))
    d.exec("ALTER TABLE entries ADD COLUMN reveal_public INTEGER NOT NULL DEFAULT 1");
  if (!hasColumn(d, "sched_salt")) d.exec("ALTER TABLE entries ADD COLUMN sched_salt TEXT");
  // Entries restored from a mirror keep the schedule commitment the chain covers, without the dates behind it.
  if (!hasColumn(d, "sched_fixed")) d.exec("ALTER TABLE entries ADD COLUMN sched_fixed TEXT");
  // Time-locked reveals (hash v4). The author's browser encrypts the opening and the hidden parts to a
  // future drand round: tl_ct is that ciphertext, tl_round its round, tl_hash the SHA-256 the chain covers.
  // tl_error is set if the ciphertext turned out not to hold a valid opening (it then never reveals).
  if (!hasColumn(d, "tl_round")) d.exec("ALTER TABLE entries ADD COLUMN tl_round INTEGER");
  if (!hasColumn(d, "tl_ct")) d.exec("ALTER TABLE entries ADD COLUMN tl_ct TEXT");
  if (!hasColumn(d, "tl_hash")) d.exec("ALTER TABLE entries ADD COLUMN tl_hash TEXT");
  if (!hasColumn(d, "tl_error")) d.exec("ALTER TABLE entries ADD COLUMN tl_error TEXT");
  // Verified drand beacon signatures already fetched, so each round is asked for once.
  d.exec("CREATE TABLE IF NOT EXISTS beacons (round INTEGER PRIMARY KEY, sig TEXT NOT NULL, at INTEGER NOT NULL)");
  if (!hasColumn(d, "hash_v")) d.exec("ALTER TABLE entries ADD COLUMN hash_v INTEGER NOT NULL DEFAULT 1");
  // 1 = commitment over the author's device key; 2 = per-entry key, commitment covers the content.
  if (!hasColumn(d, "commit_v")) d.exec("ALTER TABLE entries ADD COLUMN commit_v INTEGER NOT NULL DEFAULT 1");
  // A commitment or nonce can't be sealed twice: nobody can re-attach someone else's.
  d.exec("CREATE UNIQUE INDEX IF NOT EXISTS entries_commitment_u ON entries (commitment)");
  d.exec("CREATE UNIQUE INDEX IF NOT EXISTS entries_nonce_u ON entries (nonce)");
  // Title, place and redactions (hash v3).
  if (!hasColumn(d, "title")) d.exec("ALTER TABLE entries ADD COLUMN title TEXT NOT NULL DEFAULT ''");
  if (!hasColumn(d, "place_mode"))
    d.exec("ALTER TABLE entries ADD COLUMN place_mode TEXT NOT NULL DEFAULT 'none'");
  if (!hasColumn(d, "place_lat")) d.exec("ALTER TABLE entries ADD COLUMN place_lat REAL");
  if (!hasColumn(d, "place_lng")) d.exec("ALTER TABLE entries ADD COLUMN place_lng REAL");
  if (!hasColumn(d, "place_label")) d.exec("ALTER TABLE entries ADD COLUMN place_label TEXT");
  if (!hasColumn(d, "secret_commit")) d.exec("ALTER TABLE entries ADD COLUMN secret_commit TEXT");
  if (!hasColumn(d, "secret_pkg")) d.exec("ALTER TABLE entries ADD COLUMN secret_pkg TEXT");
  if (!hasColumn(d, "secret_blob")) d.exec("ALTER TABLE entries ADD COLUMN secret_blob TEXT");
  // Likes and dislikes. Outside the hash chain on purpose: votes change, the record doesn't.
  if (!hasColumn(d, "likes")) d.exec("ALTER TABLE entries ADD COLUMN likes INTEGER NOT NULL DEFAULT 0");
  if (!hasColumn(d, "dislikes"))
    d.exec("ALTER TABLE entries ADD COLUMN dislikes INTEGER NOT NULL DEFAULT 0");
  // One row per browser per entry. `voter` is a hash of a random token kept in that browser,
  // so a vote can't be traced back to a person or linked to their sealed entries.
  d.exec(`
    CREATE TABLE IF NOT EXISTS votes (
      entry_uid TEXT NOT NULL,
      voter     TEXT NOT NULL,
      value     INTEGER NOT NULL CHECK (value IN (-1, 1)),
      at        INTEGER NOT NULL,
      PRIMARY KEY (entry_uid, voter)
    ) WITHOUT ROWID;
  `);
  // "Did it happen?" votes, allowed once an entry is revealed. Same shape as likes.
  if (!hasColumn(d, "happened"))
    d.exec("ALTER TABLE entries ADD COLUMN happened INTEGER NOT NULL DEFAULT 0");
  if (!hasColumn(d, "not_happened"))
    d.exec("ALTER TABLE entries ADD COLUMN not_happened INTEGER NOT NULL DEFAULT 0");
  d.exec(`
    CREATE TABLE IF NOT EXISTS outcome_votes (
      entry_uid TEXT NOT NULL,
      voter     TEXT NOT NULL,
      value     INTEGER NOT NULL CHECK (value IN (-1, 1)),
      at        INTEGER NOT NULL,
      PRIMARY KEY (entry_uid, voter)
    ) WITHOUT ROWID;
  `);
  // Comments: permanent, and chained in their own hash chain like entries. Every comment
  // carries a fixed-size tag. For most it is random bytes; for an author's follow-up it is
  // an encrypted signature only holders of that entry's private link can open.
  if (!hasColumn(d, "comment_count"))
    d.exec("ALTER TABLE entries ADD COLUMN comment_count INTEGER NOT NULL DEFAULT 0");
  d.exec(`
    CREATE TABLE IF NOT EXISTS comments (
      id           INTEGER PRIMARY KEY,
      uid          TEXT NOT NULL UNIQUE,
      entry_uid    TEXT NOT NULL,
      text         TEXT NOT NULL,
      tag          TEXT NOT NULL,
      created_at   INTEGER NOT NULL,
      prev_hash    TEXT NOT NULL,
      comment_hash TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS comments_by_entry ON comments (entry_uid, id);
  `);

  // ---- Spam handling and similar-entry groups. None of this is in the entry hash chain. ----
  // Comments: the chain covers a fingerprint of the text (text_hash), so confirmed spam can
  // have its text removed while the chain still verifies. dup_hash spots repeated text.
  if (!hasColumn(d, "text_hash", "comments")) {
    d.exec("ALTER TABLE comments ADD COLUMN text_hash TEXT NOT NULL DEFAULT ''");
    d.exec("ALTER TABLE comments ADD COLUMN dup_hash TEXT NOT NULL DEFAULT ''");
    d.exec("ALTER TABLE comments ADD COLUMN reports INTEGER NOT NULL DEFAULT 0");
    d.exec("ALTER TABLE comments ADD COLUMN removed_at INTEGER");
    d.exec("ALTER TABLE comments ADD COLUMN removed_reason TEXT");
  }
  // Entries are never removed. They can be taken off the lists (still reachable by link).
  // listing: 0 = decided by reports, 1 = delisted by the admin, 2 = kept listed by the admin.
  if (!hasColumn(d, "reports")) {
    d.exec("ALTER TABLE entries ADD COLUMN reports INTEGER NOT NULL DEFAULT 0");
    d.exec("ALTER TABLE entries ADD COLUMN listing INTEGER NOT NULL DEFAULT 0");
    d.exec("ALTER TABLE entries ADD COLUMN dup_hash TEXT NOT NULL DEFAULT ''");
    // Entries that say much the same thing share a group_id (the seq of the group's first entry).
    d.exec("ALTER TABLE entries ADD COLUMN group_id INTEGER");
    d.exec("UPDATE entries SET group_id = seq WHERE group_id IS NULL");
  }
  d.exec(`
    CREATE INDEX IF NOT EXISTS comments_dup ON comments (dup_hash, created_at);
    CREATE INDEX IF NOT EXISTS entries_dup ON entries (dup_hash, created_at);
    CREATE INDEX IF NOT EXISTS entries_group ON entries (group_id);
    CREATE TABLE IF NOT EXISTS comment_reports (
      comment_id INTEGER NOT NULL,
      voter      TEXT NOT NULL,
      at         INTEGER NOT NULL,
      PRIMARY KEY (comment_id, voter)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS entry_reports (
      entry_uid TEXT NOT NULL,
      voter     TEXT NOT NULL,
      at        INTEGER NOT NULL,
      PRIMARY KEY (entry_uid, voter)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS blocked_domains (
      domain   TEXT PRIMARY KEY,
      added_at INTEGER NOT NULL
    ) WITHOUT ROWID;
    -- Word index used to find entries that say much the same thing. rowid = entries.seq.
    CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts5(body);
  `);
  // Signed chain tips (scripts/anchor.mjs), and the countersignatures of independent mirrors.
  // (The ots columns are from an earlier design and are no longer used.)
  d.exec(`
    CREATE TABLE IF NOT EXISTS anchors (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      at         INTEGER NOT NULL,
      head       TEXT NOT NULL,
      sig        TEXT NOT NULL,
      ots        BLOB,
      ots_note   TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS witness_keys (
      key      TEXT PRIMARY KEY,
      name     TEXT NOT NULL,
      added_at INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS anchor_witnesses (
      anchor_id INTEGER NOT NULL,
      key       TEXT NOT NULL,
      at        INTEGER NOT NULL,
      sig       TEXT NOT NULL,
      PRIMARY KEY (anchor_id, key)
    ) WITHOUT ROWID;
  `);
  // Private chats. The server holds only what it cannot read: ids that are hashes of secrets,
  // encrypted handshake blobs and encrypted, padded messages. Not part of the public record.
  d.exec(`
    CREATE TABLE IF NOT EXISTS chat_invites (
      id         TEXT PRIMARY KEY,
      owner_hash TEXT NOT NULL,
      hello      TEXT NOT NULL,
      max_uses   INTEGER NOT NULL,
      uses       INTEGER NOT NULL DEFAULT 0,
      closed     INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS chat_rooms (
      id         TEXT PRIMARY KEY,
      invite_id  TEXT NOT NULL,
      auth_hash  TEXT NOT NULL,
      join_blob  TEXT NOT NULL,
      ttl_ms     INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      deleted_at INTEGER
    ) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS chat_rooms_invite ON chat_rooms (invite_id, created_at);
  `);
  if (!hasChatColumn(d, "slot")) d.exec("ALTER TABLE chat_rooms ADD COLUMN slot INTEGER");
  d.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS chat_rooms_slot ON chat_rooms (invite_id, slot) WHERE slot IS NOT NULL;
    CREATE TABLE IF NOT EXISTS chat_messages (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id    TEXT NOT NULL,
      blob       TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS chat_messages_room ON chat_messages (room_id, id);
  `);
  // Posts sealed with a delayed release wait here, unpublished, until their time (lib/entries.ts).
  d.exec(`
    CREATE TABLE IF NOT EXISTS pending_entries (
      uid        TEXT PRIMARY KEY,
      commitment TEXT NOT NULL UNIQUE,
      nonce      TEXT NOT NULL UNIQUE,
      payload    TEXT NOT NULL,
      release_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    ) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS pending_due ON pending_entries (release_at);
  `);
  const indexed = d.prepare("SELECT COUNT(*) AS n FROM entries_fts").get() as { n: number };
  const total = d.prepare("SELECT COUNT(*) AS n FROM entries").get() as { n: number };
  if (Number(indexed.n) < Number(total.n))
    d.exec(`
      INSERT INTO entries_fts (rowid, body)
        SELECT seq, title || char(10) || text FROM entries
         WHERE seq NOT IN (SELECT rowid FROM entries_fts)
    `);
}

/** Opened on first use, never at import time. */
export function getDb(): DatabaseSync {
  return g.__whenisaidDb ?? (g.__whenisaidDb = open());
}

// The release log: an append-only, hash-linked list of every signed release this site has served.
//
// Each entry is the exact signed release list (data/release.json, see scripts/release.mjs) and a hash that
// covers everything before it. Mirrors keep their own copy and complain if an entry ever changes or vanishes,
// and the code checker requires that the release being served is the newest entry. So the site can't serve one
// person a release nobody else can see: a release that is not in everyone's log gets noticed.
//
//   hash(n) = SHA-256( hash(n-1) + "\n" + JSON.stringify(["zesuro-release-log-v1", seq, at, sha]) )
//   sha     = SHA-256 of the release list's exact text

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { getDb } from "./db";

const ZERO = "0".repeat(64);
const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
export const logHash = (prev: string, seq: number, at: number, sha: string) =>
  sha256(prev + "\n" + JSON.stringify(["zesuro-release-log-v1", seq, at, sha]));

function table() {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS release_log (
      seq     INTEGER PRIMARY KEY,
      at      INTEGER NOT NULL,
      sha     TEXT NOT NULL,
      release TEXT NOT NULL,
      prev    TEXT NOT NULL,
      hash    TEXT NOT NULL
    );
  `);
}

/** Adds the release now installed to the log, if it isn't the newest entry already. */
export function syncReleaseLog(now = Date.now()): void {
  let text: string;
  try {
    text = fs.readFileSync(path.join(process.cwd(), "data", "release.json"), "utf8");
  } catch {
    return; // no signed release yet
  }
  table();
  const db = getDb();
  const sha = sha256(text);
  const last = db.prepare("SELECT seq, sha, hash FROM release_log ORDER BY seq DESC LIMIT 1").get() as
    | { seq: number; sha: string; hash: string }
    | undefined;
  if (last?.sha === sha) return;
  const seq = (last?.seq ?? 0) + 1;
  const prev = last?.hash ?? ZERO;
  db.prepare("INSERT OR IGNORE INTO release_log (seq, at, sha, release, prev, hash) VALUES (?, ?, ?, ?, ?, ?)").run(
    seq,
    now,
    sha,
    text,
    prev,
    logHash(prev, seq, now, sha),
  );
}

export function readReleaseLog(after: number, limit: number) {
  syncReleaseLog();
  table();
  const db = getDb();
  const rows = db
    .prepare("SELECT seq, at, sha, release, prev, hash FROM release_log WHERE seq > ? ORDER BY seq LIMIT ?")
    .all(Math.max(0, after), Math.min(Math.max(1, limit), 200)) as unknown as {
    seq: number;
    at: number;
    sha: string;
    release: string;
    prev: string;
    hash: string;
  }[];
  const tip = db.prepare("SELECT seq, hash FROM release_log ORDER BY seq DESC LIMIT 1").get() as
    | { seq: number; hash: string }
    | undefined;
  return { count: tip?.seq ?? 0, tip: tip?.hash ?? ZERO, releases: rows.map((r) => ({ ...r, seq: Number(r.seq), at: Number(r.at) })) };
}

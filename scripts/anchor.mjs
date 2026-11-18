#!/usr/bin/env node
// Signs the current chain tips. Run every few minutes, as the app's user, from the app folder:
//   node scripts/anchor.mjs
// Nothing leaves the server. If nothing changed since the last anchor it does nothing.
// Independent mirrors fetch each anchor, check it against their own copy of the record and
// countersign it (see scripts/mirror.mjs --witness). See src/lib/anchors.ts.
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import { loadWriterKey } from "./writer-key.mjs";

const dataDir = path.resolve(process.env.DATA_DIR || "data");
const db = new DatabaseSync(path.join(dataDir, "whenisaid.db"));
db.exec("PRAGMA busy_timeout = 10000;");
db.exec(`CREATE TABLE IF NOT EXISTS anchors (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, head TEXT NOT NULL, sig TEXT NOT NULL,
  ots BLOB, ots_note TEXT NOT NULL DEFAULT ''
);`);

const ZERO = "0".repeat(64);
// The site's signing key lives next to the database and is made the first time it is needed.
// `--hybrid` makes a hybrid (Ed25519 + SLH-DSA) key instead of an Ed25519 one. See scripts/writer-key.mjs.
let writer;
try { writer = loadWriterKey(dataDir, { wantHybrid: process.argv.includes("--hybrid") }); } catch (e) { console.error(e.message); process.exit(1); }

const e = db.prepare("SELECT COUNT(*) AS n, (SELECT entry_hash FROM entries ORDER BY seq DESC LIMIT 1) AS tip FROM entries").get();
const c = db.prepare("SELECT COUNT(*) AS n, (SELECT comment_hash FROM comments ORDER BY id DESC LIMIT 1) AS tip FROM comments").get();
// The exact text that is signed and timestamped. Field order is fixed so the bytes are stable.
const body = (at) => JSON.stringify({ v: 1, at, entries: { count: Number(e.n), tip: e.tip ?? ZERO }, comments: { count: Number(c.n), tip: c.tip ?? ZERO } });

const last = db.prepare("SELECT head FROM anchors ORDER BY id DESC LIMIT 1").get();
if (last) {
  const l = JSON.parse(last.head);
  if (l.entries.tip === (e.tip ?? ZERO) && l.comments.tip === (c.tip ?? ZERO) && l.entries.count === Number(e.n) && l.comments.count === Number(c.n)) {
    console.log("Nothing new since the last anchor.");
    process.exit(0);
  }
}

const head = body(Date.now());
const sig = writer.sign("anchor", head);
db.prepare("INSERT INTO anchors (at, head, sig) VALUES (?, ?, ?)").run(JSON.parse(head).at, head, sig);
console.log(`Anchored ${e.n} entries and ${c.n} comments.`);

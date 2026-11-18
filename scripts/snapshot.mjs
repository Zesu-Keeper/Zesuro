#!/usr/bin/env node
// Writes an encrypted snapshot of the whole database for standby servers to keep. Run every few
// minutes, as the app's user, from the app folder:   node scripts/snapshot.mjs
// Needs data/authority.json (it names the recovery key). Keeps the last three snapshots.
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { currentRecovery } from "./log-core.mjs";
import { loadWriterKey } from "./writer-key.mjs";
import fs from "node:fs";
import path from "node:path";
import { sealSnapshot } from "./snapshot-core.mjs";

const dataDir = path.resolve(process.env.DATA_DIR || "data");
const authFile = path.join(dataDir, "authority.json");
if (!fs.existsSync(authFile)) { console.log("No authority.json yet, so there is no recovery key to encrypt to. Nothing written."); process.exit(0); }
const recovery = currentRecovery(JSON.parse(fs.readFileSync(authFile, "utf8"))); // the key the root signed
const out = path.join(dataDir, "snapshots");
fs.mkdirSync(out, { recursive: true, mode: 0o700 });

const db = new DatabaseSync(path.join(dataDir, "whenisaid.db"));
db.exec("PRAGMA busy_timeout = 10000;");
const tmp = path.join(out, `.plain-${process.pid}.db`);
fs.rmSync(tmp, { force: true });
let file, meta;
try {
  db.exec(`VACUUM INTO '${tmp.replace(/'/g, "''")}'`); // one consistent copy
  const copy = new DatabaseSync(tmp, { readOnly: true });
  const e = copy.prepare("SELECT COUNT(*) AS n, (SELECT entry_hash FROM entries ORDER BY seq DESC LIMIT 1) AS tip FROM entries").get();
  const c = copy.prepare("SELECT COUNT(*) AS n, (SELECT comment_hash FROM comments ORDER BY id DESC LIMIT 1) AS tip FROM comments").get();
  copy.close();
  const ZERO = "0".repeat(64);
  meta = { at: Date.now(), entries: { count: Number(e.n), tip: e.tip ?? ZERO }, comments: { count: Number(c.n), tip: c.tip ?? ZERO } };
  file = sealSnapshot(fs.readFileSync(tmp), recovery, meta);
} finally {
  // The unencrypted copy exists only for these few moments.
  try { const n = fs.statSync(tmp).size; fs.writeFileSync(tmp, Buffer.alloc(Math.min(n, 64 * 1024 * 1024))); } catch { /* already gone */ }
  fs.rmSync(tmp, { force: true });
}
const name = `snapshot-${meta.at}.zsnap`;
fs.writeFileSync(path.join(out, name), file, { mode: 0o600 });
const sha256 = createHash("sha256").update(file).digest("hex");
const manifest = { v: 1, ...meta, name, size: file.length, sha256 };
const text = JSON.stringify(manifest);
// Signed by the server's key, with the purpose "snapshot" built into the signed bytes, so a standby
// knows the snapshot came from the record's writer and the signature can't be passed off as an anchor.
// The manifest covers the file's hash, so the file can't be swapped for another encrypted to the
// (public) recovery key.
const sig = loadWriterKey(dataDir).sign("snapshot", text);
fs.writeFileSync(path.join(out, "latest.json"), JSON.stringify({ manifest: text, sig }), { mode: 0o600 });
for (const old of fs.readdirSync(out).filter((f) => f.endsWith(".zsnap")).sort().slice(0, -3)) fs.rmSync(path.join(out, old), { force: true });
console.log(`Snapshot written: ${meta.entries.count} entries, ${meta.comments.count} comments, ${file.length} bytes.`);

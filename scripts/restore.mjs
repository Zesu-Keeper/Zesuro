#!/usr/bin/env node
// Brings a replacement server up to where the failed one left off.
//
//   node scripts/restore.mjs --snapshot <file.zsnap> --recovery <recovery-key.json>
//                            --manifest <latest.json> --root <root public key> --authority <authority.json>
//                            [--log <mirror folder>] [--data data]
//
// The recovery PUBLIC key is published (it is in authority.json), so anyone could make a file that
// opens with your recovery key. A snapshot is therefore only used if its manifest was signed by the
// server the root key had delegated to at that point, and the manifest's hash matches the file.
// (--unauthenticated skips this. Use it only for a snapshot you made yourself.)
//
// 1. Opens the encrypted snapshot with the recovery key (from scripts/root.mjs) and writes it
//    as the database. That brings back everything: entries, reveals, votes, chats.
// 2. With --log, adds whatever a mirror recorded after the snapshot was taken, so the record
//    continues exactly from where the mirrors and witnesses have it. Those last few entries come
//    back with their public parts only: a scheduled reveal among them will not fire by itself
//    (its author can still reveal it with their key), and comments among them keep their place
//    and fingerprint but not their text.
// Afterwards: start the app once (or run scripts/anchor.mjs) to make this server's key, sign a
// delegation for that key with scripts/root.mjs, and put authority.json in the data folder.
// It refuses to overwrite an existing database.
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { openSnapshot } from "./snapshot-core.mjs";
import { ZERO, authorityProblem, commentHash, commentProblem, entryHash, entryProblem, snapshotSigner } from "./log-core.mjs";

const argv = process.argv.slice(2);
const opt = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
const die = (m) => { console.error(m); process.exit(1); };
const snap = opt("snapshot"), rec = opt("recovery"), log = opt("log"), dataDir = path.resolve(opt("data", "data"));
const manifestFile = opt("manifest"), root = opt("root"), authorityFile = opt("authority"), unauthenticated = argv.includes("--unauthenticated");
if (!snap || !rec) die("Use: restore --snapshot <file.zsnap> --recovery <recovery-key.json> --manifest <latest.json> --root <root key> --authority <authority.json> [--log <mirror folder>] [--data data]");
const dbFile = path.join(dataDir, "whenisaid.db");
if (fs.existsSync(dbFile)) die(`${dbFile} already exists. Move it away first; this tool never overwrites a database.`);

const snapBytes = fs.readFileSync(snap);
let manifest = null;
if (unauthenticated) console.log("WARNING: --unauthenticated. Nothing proves this snapshot came from the record's writer.");
else {
  if (!manifestFile || !root || !authorityFile) die("Refusing: a snapshot is only trusted with --manifest, --root and --authority (or --unauthenticated for a snapshot you made yourself).");
  let auth, m;
  try { auth = JSON.parse(fs.readFileSync(authorityFile, "utf8")); m = JSON.parse(fs.readFileSync(manifestFile, "utf8")); } catch (e) { die(`Could not read the authority or manifest file: ${e.message}`); }
  const bad = authorityProblem(auth, root);
  if (bad) die(`The authority file is not valid for that root key: ${bad}`);
  const writer = snapshotSigner({ auth, siteKey: null }, String(m?.manifest), m?.sig);
  if (!writer) die("The manifest was not signed by a server the root key delegated to for that point in the record. Not using this snapshot.");
  manifest = JSON.parse(m.manifest);
  if (createHash("sha256").update(snapBytes).digest("hex") !== manifest.sha256 || snapBytes.length !== manifest.size) die("The snapshot file is not the one the signed manifest describes. Not using it.");
  console.log(`Manifest verified: signed by ${writer.slice(0, 16)}…, root key ${root.slice(0, 16)}…`);
}

let opened;
try { opened = openSnapshot(snapBytes, fs.readFileSync(rec)); } catch (e) { die(`Could not open the snapshot: ${e.message}`); }
fs.mkdirSync(dataDir, { recursive: true });
fs.writeFileSync(dbFile, opened.plain, { mode: 0o600 });
const db = new DatabaseSync(dbFile);
const count = (t) => Number(db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n);
const tipE = () => db.prepare("SELECT entry_hash AS h FROM entries ORDER BY seq DESC LIMIT 1").get()?.h ?? ZERO;
const tipC = () => db.prepare("SELECT comment_hash AS h FROM comments ORDER BY id DESC LIMIT 1").get()?.h ?? ZERO;
if (manifest && (manifest.entries.count !== opened.header.entries.count || manifest.entries.tip !== opened.header.entries.tip || manifest.comments.count !== opened.header.comments.count || manifest.comments.tip !== opened.header.comments.tip)) die("The signed manifest and the snapshot's own header disagree. Not using it.");
if (count("entries") !== opened.header.entries.count || tipE() !== opened.header.entries.tip) die("The snapshot's contents do not match its own header. Not using it.");
console.log(`Snapshot of ${new Date(opened.header.at).toISOString()} restored: ${count("entries")} entries, ${count("comments")} comments.`);

if (log) {
  const lines = (f) => (fs.existsSync(path.join(log, f)) ? fs.readFileSync(path.join(log, f), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
  const entries = lines("entries.jsonl"), comments = lines("comments.jsonl");
  const have = count("entries");
  // The mirror's copy must be the same record as the snapshot, as far as the snapshot goes.
  if (entries.length < have || (have > 0 && entries[have - 1].entryHash !== tipE())) die("The mirror's record is not a continuation of this snapshot. Stopping: do not start this server until that is understood.");
  const cols = new Set(db.prepare("PRAGMA table_info(entries)").all().map((c) => c.name));
  if (!cols.has("sched_fixed")) db.exec("ALTER TABLE entries ADD COLUMN sched_fixed TEXT");
  for (const c of ["tl_round INTEGER", "tl_ct TEXT", "tl_hash TEXT", "tl_error TEXT", "mailbox_root TEXT", "witness_round INTEGER", "witness_sig TEXT"]) if (!cols.has(c.split(" ")[0])) db.exec(`ALTER TABLE entries ADD COLUMN ${c}`);
  db.exec("BEGIN IMMEDIATE");
  let prev = tipE(), addedE = 0, addedC = 0;
  // A restored entry has no dates behind its schedule commitment. If the mirror holds its time-lock (a public reveal
  // date), the unlock time follows from the round, so the entry can still open itself when that round comes.
  const roundTime = (r) => (1692803367 + (r - 1) * 3) * 1000; // drand quicknet: round 1 is at genesis, one round every 3 s
  const insE = db.prepare(`INSERT INTO entries (seq, uid, text, commitment, nonce, created_at, mode, reveal_at, deadline_at, prev_hash, entry_hash,
      reveal_pkg, reveal_public, sched_salt, hash_v, commit_v, title, place_mode, place_lat, place_lng, place_label, secret_commit, sched_fixed, group_id, tl_round, tl_ct, tl_hash, mailbox_root, witness_round, witness_sig)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, 0, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  for (const x of entries.slice(have)) {
    if (entryProblem(x) || x.prevHash !== prev || entryHash(prev, x) !== x.entryHash) { db.exec("ROLLBACK"); die(`The mirror's entry ${x?.seq} does not verify. Nothing was added.`); }
    const p = x.placeMode === "public" ? x.place : null;
    insE.run(x.seq, x.uid, x.text, x.commitment, x.nonce, x.createdAt, x.mode, x.tl ? roundTime(x.tl.round) : null, x.prevHash, x.entryHash, x.hashV, x.commitV ?? 1, x.title, x.placeMode, p?.lat ?? null, p?.lng ?? null, p?.label ?? null, x.secretCommit, x.schedCommit, x.seq, x.tl?.round ?? null, x.tl?.ct ?? null, x.tlHash ?? null, x.mailboxRoot ?? null, x.witnessRound ?? null, x.witnessSig ?? null);
    try { db.prepare("INSERT INTO entries_fts (rowid, body) VALUES (?, ?)").run(x.seq, `${x.title}\n${x.text}`); } catch { /* search index is optional */ }
    prev = x.entryHash;
    addedE++;
  }
  const haveC = count("comments");
  if (comments.length < haveC || (haveC > 0 && comments[haveC - 1].commentHash !== tipC())) { db.exec("ROLLBACK"); die("The mirror's comments are not a continuation of this snapshot. Nothing was added."); }
  prev = tipC();
  const now = Date.now();
  const insC = db.prepare(`INSERT INTO comments (id, uid, entry_uid, text, text_hash, dup_hash, tag, created_at, prev_hash, comment_hash, removed_at, removed_reason)
    VALUES (?, ?, ?, '', ?, '', ?, ?, ?, ?, ?, 'text lost when the record moved to a new server')`);
  for (const x of comments.slice(haveC)) {
    if (commentProblem(x) || x.prevHash !== prev || commentHash(prev, x) !== x.commentHash) { db.exec("ROLLBACK"); die(`The mirror's comment ${x?.id} does not verify. Nothing was added.`); }
    insC.run(x.id, x.uid, x.entryUid, x.textHash, x.tag, x.createdAt, x.prevHash, x.commentHash, now);
    db.prepare("UPDATE entries SET comment_count = comment_count + 1 WHERE uid = ?").run(x.entryUid);
    prev = x.commentHash;
    addedC++;
  }
  // The signed tips the old server published after the snapshot are history too: keep them, so
  // this server's own continue the numbering the mirrors already know.
  const haveA = Number(db.prepare("SELECT COALESCE(MAX(id), 0) AS m FROM anchors").get().m);
  for (const a2 of lines("anchors.jsonl").filter((x) => x.id > haveA).sort((x, y) => x.id - y.id))
    db.prepare("INSERT INTO anchors (id, at, head, sig) VALUES (?, ?, ?, ?)").run(a2.id, a2.at, a2.head, a2.sig);
  db.exec("COMMIT");
  console.log(`From the mirror: ${addedE} later entr${addedE === 1 ? "y" : "ies"} and ${addedC} later comment(s) added, public parts only.`);
}
// The old server's signing key must not come along: this server makes its own. (The tips the
// old server signed stay in the record; the root's delegations say which key signed which part.)
for (const f of ["anchor-key.pem", "anchor-key.pub"]) fs.rmSync(path.join(dataDir, f), { force: true });
db.close();
console.log(`The record now stands at ${count2()}.\nNext: run scripts/anchor.mjs to make this server's key, sign a delegation for it with scripts/root.mjs, and put authority.json in ${dataDir}.`);
function count2() { const d = new DatabaseSync(dbFile, { readOnly: true }); const r = `${d.prepare("SELECT COUNT(*) AS n FROM entries").get().n} entries, ${d.prepare("SELECT COUNT(*) AS n FROM comments").get().n} comments`; d.close(); return r; }

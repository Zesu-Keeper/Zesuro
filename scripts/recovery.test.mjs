// Disaster recovery, end to end: a server with a record and a private schedule is snapshotted,
// "lost", and a replacement continues from the snapshot plus a mirror's copy. Also: forged and
// tampered snapshots are refused.
// Run: node --no-warnings --import ./scripts/ts-resolve.mjs scripts/recovery.test.mjs
// (one hybrid signature is made, so it takes about a minute)
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import * as hybrid from "./hybrid-sig.mjs";
import { ZERO, commentHash, entryHash, writerBytes } from "./log-core.mjs";
import { sealSnapshot } from "./snapshot-core.mjs";

const sha = (s) => createHash("sha256").update(s).digest("hex");
const H = (c) => c.repeat(64);

// ------------------------------------------------------------------ child modes (run with a data folder as cwd)
if (process.argv[2] === "seed" || process.argv[2] === "late" || process.argv[2] === "inspect") {
  const mode = process.argv[2], mirrorDir = process.argv[3];
  const { getDb } = await import("../src/lib/db.ts");
  const { listLog, verifyChain } = await import("../src/lib/entries.ts");
  const { listCommentLog } = await import("../src/lib/comments.ts");
  const { timelockEncrypt } = await import("../src/lib/timelock.ts");
  const db = getDb();
  const lastE = () => db.prepare("SELECT seq, entry_hash AS h FROM entries ORDER BY seq DESC LIMIT 1").get();
  const lastC = () => db.prepare("SELECT id, comment_hash AS h FROM comments ORDER BY id DESC LIMIT 1").get();
  function addEntry(uid, { title, text, schedule, tl }) {
    const prev = lastE(), seq = (prev?.seq ?? 0) + 1;
    const salt = sha(uid + "salt"), revealAt = schedule ? 4102444800000 : null; // a private date far ahead
    const schedCommit = sha(JSON.stringify([revealAt, null, schedule ? salt : ""])); // no schedule: no salt
    // A time-locked entry (hash v4) with a public reveal date, so the log carries its ciphertext too.
    const ct = tl ? timelockEncrypt(new TextEncoder().encode("a bundle would be here"), 5_000_000_000) : null;
    const x = { seq, uid, createdAt: 1700000000000 + seq, title, text, commitment: sha(uid + "c"), nonce: sha(uid + "n").slice(0, 32), mode: schedule ? "date" : "manual", schedCommit, placeMode: "none", secretCommit: null,
      ...(tl ? { hashV: 4, tlHash: sha(ct) } : {}) };
    const hash = entryHash(prev?.h ?? ZERO, x);
    db.prepare(`INSERT INTO entries (seq, uid, text, commitment, nonce, created_at, mode, reveal_at, deadline_at, prev_hash, entry_hash, reveal_public, sched_salt, hash_v, commit_v, title, place_mode, secret_commit, group_id, tl_round, tl_ct, tl_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, 2, ?, 'none', NULL, ?, ?, ?, ?)`)
      .run(seq, uid, text, x.commitment, x.nonce, x.createdAt, x.mode, revealAt, prev?.h ?? ZERO, hash, tl ? 1 : 0, schedule ? salt : null, tl ? 4 : 3, title, seq, tl ? 5_000_000_000 : null, ct, tl ? x.tlHash : null);
    db.prepare("INSERT INTO entries_fts (rowid, body) VALUES (?, ?)").run(seq, `${title}\n${text}`);
    return hash;
  }
  function addComment(uid, entryUid, text) {
    const prev = lastC(), id = (prev?.id ?? 0) + 1;
    const x = { id, uid, entryUid, createdAt: 1700000001000 + id, textHash: sha(text), tag: "t".repeat(20) };
    const hash = commentHash(prev?.h ?? ZERO, x);
    db.prepare("INSERT INTO comments (id, uid, entry_uid, text, tag, created_at, prev_hash, comment_hash, text_hash, dup_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '')")
      .run(id, uid, entryUid, text, x.tag, x.createdAt, prev?.h ?? ZERO, hash, x.textHash);
  }
  const dump = () => {
    fs.mkdirSync(mirrorDir, { recursive: true });
    fs.writeFileSync(path.join(mirrorDir, "entries.jsonl"), listLog(0, 1000).map((x) => JSON.stringify(x) + "\n").join(""));
    fs.writeFileSync(path.join(mirrorDir, "comments.jsonl"), listCommentLog(0, 1000).map((x) => JSON.stringify(x) + "\n").join(""));
    fs.writeFileSync(path.join(mirrorDir, "anchors.jsonl"), "");
  };
  if (mode === "seed") {
    addEntry("e-one", { title: "First", text: "plain post" });
    addEntry("e-two", { title: "Second", text: "has a private reveal date", schedule: true });
    addEntry("e-three", { title: "Third", text: "another" });
    addComment("c-one", "e-one", "a comment");
    console.log(JSON.stringify({ chain: verifyChain() }));
  } else if (mode === "late") {
    addEntry("e-four", { title: "After the snapshot", text: "made after the last snapshot", schedule: true });
    addEntry("e-five", { title: "Time-locked after the snapshot", text: "made after the snapshot, with a time-lock", schedule: true, tl: true });
    addComment("c-two", "e-four", "a later comment");
    dump();
    console.log(JSON.stringify({ chain: verifyChain() }));
  } else {
    const rows = listLog(0, 1000);
    const c = db.prepare("SELECT COUNT(*) AS n FROM comments").get().n;
    const removed = db.prepare("SELECT COUNT(*) AS n FROM comments WHERE removed_at IS NOT NULL").get().n;
    const t5 = db.prepare("SELECT hash_v, tl_round, tl_ct IS NOT NULL AS has_ct, tl_hash, reveal_at FROM entries WHERE uid = 'e-five'").get();
    console.log(JSON.stringify({ chain: verifyChain(), sched: rows.map((r) => r.schedCommit), comments: Number(c), removed: Number(removed), tl: rows.map((r) => r.tlHash ?? null), t5: t5 ? { ...t5 } : null }));
  }
  process.exit(0);
}

// ------------------------------------------------------------------ the test
let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const tmp = fs.mkdtempSync(path.join(os.homedir(), ".zesuro-recovery-test-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));
const run = (file, args, cwd, env = {}) => spawnSync(process.execPath, ["--no-warnings", "--experimental-transform-types", "--import", path.resolve("scripts/ts-resolve.mjs"), path.resolve(file), ...args], { cwd, encoding: "utf8", env: { ...process.env, ...env } });
const mk = (d) => { fs.mkdirSync(d, { recursive: true }); return d; };

const A = mk(path.join(tmp, "serverA")), rootDir = path.join(tmp, "root"), mirrorDir = path.join(tmp, "mirror");
const mine = (r, label) => { assert.equal(r.status, 0, `${label}: ${r.stdout}${r.stderr}`); return r.stdout; };

// Server A: a record with a private schedule and a comment
let out = JSON.parse(mine(run(process.argv[1], ["seed", mirrorDir], A), "seed").trim().split("\n").pop());
ok(out.chain.ok && out.chain.count === 3, "the app's own chain check accepts rows built with the standalone formulas");

// The root key, and server A's signing key, delegated from the start of the record
mine(run("scripts/root.mjs", ["init", "--dir", rootDir], tmp), "root init");
const root = hybrid.publicKeyOf(fs.readFileSync(path.join(rootDir, "root-key.json"), "utf8"));
mine(run("scripts/anchor.mjs", [], A, { DATA_DIR: path.join(A, "data") }), "anchor");
const writerKey = fs.readFileSync(path.join(A, "data", "anchor-key.pub"), "utf8").trim();
const authFile = path.join(A, "data", "authority.json");
mine(run("scripts/root.mjs", ["delegate", "--writer", writerKey, "--from", "genesis", "--dir", rootDir, "--authority", authFile], tmp), "delegate");
mine(run("scripts/snapshot.mjs", [], A, { DATA_DIR: path.join(A, "data") }), "snapshot");
const snapDir = path.join(A, "data", "snapshots");
const snapFile = path.join(snapDir, fs.readdirSync(snapDir).find((f) => f.endsWith(".zsnap")));
const manifest = path.join(snapDir, "latest.json");
const recoveryPem = path.join(rootDir, "recovery-key.json");
ok(fs.statSync(snapFile).mode & 0o077 ? false : true, "snapshot file is private to its owner");

// More happens after the snapshot; a mirror holds all of it
mine(run(process.argv[1], ["late", mirrorDir], A), "late");

// Replacement server B
const restore = (dataDir, extra) => run("scripts/restore.mjs", ["--snapshot", snapFile, "--recovery", recoveryPem, "--data", dataDir, ...extra], tmp);
const B = mk(path.join(tmp, "serverB"));
let r = restore(path.join(B, "data"), ["--manifest", manifest, "--root", root, "--authority", authFile, "--log", mirrorDir]);
ok(r.status === 0 && /Manifest verified/.test(r.stdout) && /2 later entries and 1 later comment/.test(r.stdout), "authenticated restore with the mirror's later records\n" + r.stdout + r.stderr);
out = JSON.parse(mine(run(process.argv[1], ["inspect", mirrorDir], B), "inspect").trim().split("\n").pop());
ok(out.chain.ok && out.chain.count === 5, "the replacement's own chain check passes over the restored and the mirror-added entries (including a v4 one)");
ok(out.sched.length === 5 && out.sched.every((s) => /^[0-9a-f]{64}$/.test(s)), "every entry, including the one restored from the mirror, shows its schedule commitment");
const mirrorSched = fs.readFileSync(path.join(mirrorDir, "entries.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l).schedCommit);
ok(JSON.stringify(out.sched) === JSON.stringify(mirrorSched), "and they are exactly the commitments the original server published");
ok(out.t5 && out.t5.hash_v === 4 && out.t5.tl_round === 5_000_000_000 && out.t5.has_ct === 1 && /^[0-9a-f]{64}$/.test(out.t5.tl_hash), "a time-locked entry restored from the mirror keeps its version, round, ciphertext and hash");
ok(out.t5.reveal_at === (1692803367 + (5_000_000_000 - 1) * 3) * 1000, "and its unlock time follows from the round, so it can still open itself");
ok(out.tl.slice(0, 4).every((h) => h === null) && out.tl[4] === out.t5.tl_hash, "only that entry has a time-lock hash");
ok(out.comments === 2 && out.removed === 1, "the later comment keeps its place but its text is marked lost");
ok(!fs.existsSync(path.join(B, "data", "anchor-key.pem")), "the old server's signing key is not carried over");

// Refusals
const refuse = (name, dir, extra, pattern) => { const q = restore(path.join(tmp, dir, "data"), extra); ok(q.status !== 0 && pattern.test(q.stderr) && !fs.existsSync(path.join(tmp, dir, "data", "whenisaid.db")), `${name}\n${q.stdout}${q.stderr}`); };
refuse("no manifest, root or authority: refused", "r1", [], /Refusing: a snapshot is only trusted/);
refuse("a different root key: refused", "r2", ["--manifest", manifest, "--root", hybrid.generate().publicKey, "--authority", authFile], /not valid for that root key/);
// Tampered snapshot (one byte flipped): the manifest's hash no longer matches
const tampered = path.join(tmp, "tampered.zsnap"); const bytes = fs.readFileSync(snapFile); bytes[bytes.length - 40] ^= 1; fs.writeFileSync(tampered, bytes);
{ const q = run("scripts/restore.mjs", ["--snapshot", tampered, "--recovery", recoveryPem, "--data", path.join(tmp, "r3", "data"), "--manifest", manifest, "--root", root, "--authority", authFile], tmp);
  ok(q.status !== 0 && /not the one the signed manifest describes/.test(q.stderr), "a tampered snapshot is refused\n" + q.stderr); }
// A forged snapshot: the recovery key is public, so anyone can encrypt to it. Signed by a key the root never delegated to.
{
  const recPub = JSON.parse(fs.readFileSync(authFile, "utf8")).recovery;
  const fake = sealSnapshot(Buffer.from("SQLite format 3\0 pretend database"), recPub, { at: Date.now(), entries: { count: 0, tip: ZERO }, comments: { count: 0, tip: ZERO } });
  const fakeFile = path.join(tmp, "fake.zsnap"); fs.writeFileSync(fakeFile, fake);
  const rogue = generateKeyPairSync("ed25519");
  const text = JSON.stringify({ v: 1, at: Date.now(), entries: { count: 0, tip: ZERO }, comments: { count: 0, tip: ZERO }, name: "fake.zsnap", size: fake.length, sha256: sha(fake).length === 64 ? createHash("sha256").update(fake).digest("hex") : "" });
  const fm = path.join(tmp, "fake-latest.json");
  fs.writeFileSync(fm, JSON.stringify({ manifest: text, sig: edSign(null, writerBytes("snapshot", text), rogue.privateKey).toString("base64url") }));
  const q = run("scripts/restore.mjs", ["--snapshot", fakeFile, "--recovery", recoveryPem, "--data", path.join(tmp, "r4", "data"), "--manifest", fm, "--root", root, "--authority", authFile], tmp);
  ok(q.status !== 0 && /not signed by a server the root key delegated/.test(q.stderr), "a forged snapshot signed by an undelegated key is refused\n" + q.stderr);
  // The real writer's signature over the real manifest cannot be moved onto the forged one
  const real = JSON.parse(fs.readFileSync(manifest, "utf8"));
  fs.writeFileSync(fm, JSON.stringify({ manifest: text, sig: real.sig }));
  const q2 = run("scripts/restore.mjs", ["--snapshot", fakeFile, "--recovery", recoveryPem, "--data", path.join(tmp, "r5", "data"), "--manifest", fm, "--root", root, "--authority", authFile], tmp);
  ok(q2.status !== 0, "a genuine signature cannot be moved onto a forged manifest");
  // A snapshot signature must not pass as an anchor signature, or the reverse
  const { writerVerify } = await import("./log-core.mjs");
  ok(!writerVerify(writerKey, real.manifest, real.sig), "a snapshot signature is not accepted as an anchor signature");
}
// The unauthenticated escape hatch exists, and is loud
r = restore(path.join(tmp, "r6", "data"), ["--unauthenticated"]);
ok(r.status === 0 && /WARNING: --unauthenticated/.test(r.stdout), "--unauthenticated works but warns");

console.log(`All ${n} recovery checks passed`);

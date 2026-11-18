#!/usr/bin/env node
// The root of trust for a Zesuro record. Run this on a machine you control, NOT on the server:
// whoever holds the root key decides which server may write the record.
//
//   node scripts/root.mjs init [--dir zesuro-root]
//       Makes the hybrid root key (signs delegations) and the hybrid recovery key (opens encrypted
//       snapshots; X25519 + ML-KEM-768, so recorded snapshots stay safe from a future quantum computer).
//       Prints their public halves. Keep the folder offline, and keep a second copy somewhere safe.
//
//   node scripts/root.mjs delegate --writer <server key> --from <site url | mirror folder | genesis>
//                                  [--dir zesuro-root] [--authority authority.json]
//       Signs "this server key is the record's writer from this point on". The point is the
//       number of entries and comments (or `genesis`, the very start), and the chain tips there, read from the site or (after a
//       failure) from a mirror's copy. Appends the delegation to authority.json; put that file in
//       the server's data folder. A new delegation ends the previous server's authority beyond
//       that point, so a lost or seized server can't keep writing.
//
// Mirrors and verifiers pin the root key and accept a signed tip only from the server the root
// has delegated to for that part of the record. The root key is hybrid: every delegation carries an Ed25519 and an SLH-DSA signature, and both must verify (scripts/hybrid-sig.mjs).
import fs from "node:fs";
import path from "node:path";
import * as hybrid from "./hybrid-sig.mjs";
import { generateRecovery, recoveryPublicOf } from "./snapshot-core.mjs";
import { ZERO, authorityProblem } from "./log-core.mjs";

const argv = process.argv.slice(2);
const cmd = argv[0];
const opt = (name, d) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : d; };
const die = (m) => { console.error(m); process.exit(1); };
const dir = path.resolve(opt("dir", "zesuro-root"));
const rootFile = path.join(dir, "root-key.json"), recFile = path.join(dir, "recovery-key.json");
const rootPub = () => hybrid.publicKeyOf(fs.readFileSync(rootFile, "utf8"));
const recPub = () => recoveryPublicOf(fs.readFileSync(recFile, "utf8"));

if (cmd === "init") {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (fs.existsSync(rootFile)) die(`${rootFile} already exists. Refusing to replace a root key.`);
  fs.writeFileSync(rootFile, hybrid.generate().secret, { mode: 0o600 });
  fs.writeFileSync(recFile, generateRecovery().secret, { mode: 0o600 });
  console.log(`Root key made in ${dir}\n  root public key (zs1, Ed25519 + SLH-DSA): ${rootPub()}\n  recovery public key (zk1, X25519 + ML-KEM-768): ${recPub().slice(0, 60)}…\nKeep this folder off the server, with a second copy elsewhere. Losing it means nobody can ever authorise a replacement server or open a snapshot.`);
} else if (cmd === "delegate") {
  const writer = opt("writer"), from = opt("from"), authFile = path.resolve(opt("authority", "authority.json"));
  if (!(/^[A-Za-z0-9_-]{43}$/.test(writer || "") || hybrid.isHybridKey(writer)) || !from) die("Use: delegate --writer <server key> --from <site url | mirror folder | genesis> [--dir zesuro-root] [--authority authority.json]");
  if (!fs.existsSync(rootFile)) die(`No root key in ${dir}. Run init first.`);
  // Where the new writer takes over: the record as it stands at the source.
  let point;
  if (from === "genesis") {
    // The very start of the record. Use this for the first delegation of an existing site, so
    // that anchors it signed before delegations existed are covered too.
    point = { entries: { count: 0, tip: ZERO }, comments: { count: 0, tip: ZERO } };
  } else if (/^https?:\/\//.test(from)) {
    const c = await (await fetch(from.replace(/\/+$/, "") + "/api/chain")).json();
    if (c.ok !== true) die("That site's own chain check fails. Take the point from a mirror instead.");
    point = { entries: { count: c.count, tip: c.tip }, comments: { count: c.comments.count, tip: c.comments.tip } };
  } else {
    const lines = (f) => (fs.existsSync(path.join(from, f)) ? fs.readFileSync(path.join(from, f), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
    const e = lines("entries.jsonl"), c = lines("comments.jsonl");
    point = { entries: { count: e.length, tip: e.length ? e[e.length - 1].entryHash : ZERO }, comments: { count: c.length, tip: c.length ? c[c.length - 1].commentHash : ZERO } };
  }
  const root = rootPub();
  const auth = fs.existsSync(authFile) ? JSON.parse(fs.readFileSync(authFile, "utf8")) : { v: 1, root, recovery: recPub(), delegations: [] };
  if (auth.root !== root) die("That authority file belongs to a different root key.");
  const bad = authorityProblem(auth, root);
  if (bad) die(`The existing authority file is not valid: ${bad}`);
  // The recovery key goes inside what the root signs, so it can't be swapped without the root key.
  const head = JSON.stringify({ v: 1, type: "delegation", serial: auth.delegations.length + 1, writer, recovery: recPub(), from: point, at: Date.now() });
  auth.recovery = recPub();
  auth.delegations.push({ head, sig: hybrid.sign(fs.readFileSync(rootFile, "utf8"), "delegation", head) });
  const after = authorityProblem(auth, root);
  if (after) die(`Refusing to sign: ${after}`);
  fs.writeFileSync(authFile, JSON.stringify(auth, null, 2) + "\n");
  console.log(`Delegation ${auth.delegations.length} signed: ${writer} writes the record from entry ${point.entries.count} and comment ${point.comments.count} on.\nWritten to ${authFile}. Put it in the server's data folder as authority.json.`);
} else {
  console.log("Commands: init | delegate   (see the top of this file)");
  process.exit(cmd ? 1 : 0);
}

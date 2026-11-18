#!/usr/bin/env node
// Makes and signs the list of hashes of every script and stylesheet in a build, so that mirrors
// and anyone else can check what the site serves (scripts/code-check.mjs).
//
//   node scripts/release.mjs hash [--static .next/static] [--out release-draft.json]
//       Lists every .js and .css file under the build's static folder with its SHA-256, and the git
//       commit if there is one. Run where the build is made.
//
//   node scripts/release.mjs sign --draft release-draft.json [--dir zesuro-root] [--out release.json]
//       Signs the list with the root key (hybrid: Ed25519 + SLH-DSA, purpose "release"). Run on the
//       machine that holds the root key, after you have looked at the list. Put release.json in the
//       server's data folder; it is served at /api/release.
//
// What you are signing is "these are the files I mean the site to serve". If you build on the
// server, you are trusting the server's build. For more assurance, build on your own machine from
// the same commit, run `hash` there, and compare the two lists before signing.
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import * as hybrid from "./hybrid-sig.mjs";

const argv = process.argv.slice(2), cmd = argv[0];
const opt = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
const die = (m) => { console.error(m); process.exit(1); };

function walk(dir, base, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, base, out);
    else if (e.isFile() && /\.(js|css)$/.test(e.name)) out[`/_next/static/${path.relative(base, p).split(path.sep).join("/")}`] = createHash("sha256").update(fs.readFileSync(p)).digest("hex");
  }
}

if (cmd === "hash") {
  const dir = path.resolve(opt("static", ".next/static")), outFile = path.resolve(opt("out", "release-draft.json"));
  if (!fs.existsSync(dir)) die(`${dir} does not exist. Run the build first.`);
  const files = {};
  walk(dir, dir, files);
  const sorted = Object.fromEntries(Object.entries(files).sort(([a], [b]) => (a < b ? -1 : 1)));
  let commit = null;
  try { commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(); } catch { /* not a git checkout */ }
  fs.writeFileSync(outFile, JSON.stringify({ v: 1, commit, at: Date.now(), files: sorted }, null, 2) + "\n");
  console.log(`${Object.keys(sorted).length} files listed in ${outFile}${commit ? ` (commit ${commit.slice(0, 12)})` : ""}.\nLook it over, then sign it where the root key is: node scripts/release.mjs sign --draft ${path.basename(outFile)}`);
} else if (cmd === "sign") {
  const draft = opt("draft"), dir = path.resolve(opt("dir", "zesuro-root")), outFile = path.resolve(opt("out", "release.json"));
  if (!draft || !fs.existsSync(draft)) die("Use: sign --draft release-draft.json [--dir zesuro-root] [--out release.json]");
  const keyFile = path.join(dir, "root-key.json");
  if (!fs.existsSync(keyFile)) die(`No root key in ${dir}.`);
  const j = JSON.parse(fs.readFileSync(draft, "utf8"));
  if (j?.v !== 1 || typeof j.files !== "object" || !Object.keys(j.files).length) die("That is not a release draft, or it lists no files.");
  const manifest = JSON.stringify(j); // exactly these bytes are signed and served
  const secret = fs.readFileSync(keyFile, "utf8");
  fs.writeFileSync(outFile, JSON.stringify({ manifest, sig: hybrid.sign(secret, "release", manifest) }) + "\n");
  console.log(`Signed ${Object.keys(j.files).length} files with root key ${hybrid.publicKeyOf(secret).slice(0, 24)}…\nWritten to ${outFile}. Put it in the server's data folder as release.json.`);
} else {
  console.log("Commands: hash | sign   (see the top of this file)");
  process.exit(cmd ? 1 : 0);
}

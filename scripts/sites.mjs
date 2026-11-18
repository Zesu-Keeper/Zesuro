#!/usr/bin/env node
// The root-signed directory of mirrors and known impostor sites. Run where the root key is.
//
//   node scripts/sites.mjs add-mirror    --url https://mirror.example --name "Name" [--key <site key>] [--note "..."]
//   node scripts/sites.mjs add-malicious [--url https://fake.example] [--key <key>] --reason "..."
//   node scripts/sites.mjs remove        --url https://x.example | --key <key>      (from either list)
//   node scripts/sites.mjs list
//   node scripts/sites.mjs sign   [--dir zesuro-root] [--out sites.json]
//   node scripts/sites.mjs verify --file sites.json --root <root public key> [--min-serial N]
//
// Edits go into sites-draft.json (not signed). `sign` writes sites.json with the next serial number;
// put it in the server's data folder, where it is served at /api/sites and shown on /sites.
// "Malicious" means: a site or key that is NOT part of this record and must not be trusted to sign or
// publish it. The root signs the claim "these are the mirrors I vouch for, and these are impostors".
import fs from "node:fs";
import path from "node:path";
import * as hybrid from "./hybrid-sig.mjs";
import { manifestProblem, normUrl, sitesProblem } from "./sites-core.mjs";

const argv = process.argv.slice(2), cmd = argv[0];
const opt = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
const die = (m) => { console.error(m); process.exit(1); };
const draftFile = path.resolve(opt("draft", "sites-draft.json"));
const load = () => (fs.existsSync(draftFile) ? JSON.parse(fs.readFileSync(draftFile, "utf8")) : { v: 1, serial: 0, at: 0, mirrors: [], malicious: [] });
const save = (d) => { const bad = manifestProblem({ ...d, serial: Math.max(1, d.serial), at: d.at || 1 }); if (bad) die(`Refusing: ${bad}`); fs.writeFileSync(draftFile, JSON.stringify(d, null, 2) + "\n"); };
const url = (u) => { const x = normUrl(u); if (!x) die("--url must be a plain https address such as https://example.org (no path, no credentials)"); return x; };

if (cmd === "add-mirror") {
  const d = load(), u = url(opt("url")), name = opt("name");
  if (!name) die("--name is required");
  d.mirrors = d.mirrors.filter((s) => s.url !== u);
  d.mirrors.push({ url: u, name, ...(opt("key") ? { key: opt("key") } : {}), ...(opt("note") ? { note: opt("note") } : {}), at: Date.now() });
  save(d); console.log(`Mirror ${u} added to the draft. Run sign to publish.`);
} else if (cmd === "add-malicious") {
  const d = load(), u = opt("url") ? url(opt("url")) : undefined, key = opt("key"), reason = opt("reason");
  if (!u && !key) die("Give --url and/or --key"); if (!reason) die("--reason is required");
  d.mirrors = d.mirrors.filter((s) => !(u && s.url === u) && !(key && s.key === key));
  d.malicious.push({ ...(u ? { url: u } : {}), ...(key ? { key } : {}), reason, at: Date.now() });
  save(d); console.log(`Marked malicious in the draft: ${u ?? ""} ${key ? key.slice(0, 24) + "…" : ""}. Run sign to publish.`);
} else if (cmd === "remove") {
  const d = load(), u = opt("url") ? url(opt("url")) : undefined, key = opt("key");
  if (!u && !key) die("Give --url or --key");
  const hit = (s) => (u && s.url === u) || (key && s.key === key);
  const n = d.mirrors.length + d.malicious.length;
  d.mirrors = d.mirrors.filter((s) => !hit(s)); d.malicious = d.malicious.filter((s) => !hit(s));
  if (d.mirrors.length + d.malicious.length === n) die("Nothing matched.");
  save(d); console.log("Removed from the draft. Run sign to publish.");
} else if (cmd === "list") {
  const d = load();
  console.log(`Mirrors (${d.mirrors.length}):`); for (const s of d.mirrors) console.log(`  ${s.url}  ${s.name}${s.key ? `  key ${s.key.slice(0, 20)}…` : ""}`);
  console.log(`Malicious (${d.malicious.length}):`); for (const s of d.malicious) console.log(`  ${s.url ?? "(key only)"}${s.key ? `  key ${s.key.slice(0, 20)}…` : ""}  : ${s.reason}`);
} else if (cmd === "sign") {
  const dir = path.resolve(opt("dir", "zesuro-root")), out = path.resolve(opt("out", "sites.json")), keyFile = path.join(dir, "root-key.json");
  if (!fs.existsSync(keyFile)) die(`No root key in ${dir}.`);
  const d = load();
  // the next serial is one more than the draft's and than any file already written at --out
  let prev = d.serial; try { prev = Math.max(prev, JSON.parse(JSON.parse(fs.readFileSync(out, "utf8")).manifest).serial); } catch { /* none yet */ }
  const m = { v: 1, serial: prev + 1, at: Date.now(), mirrors: d.mirrors, malicious: d.malicious };
  const bad = manifestProblem(m); if (bad) die(`Refusing to sign: ${bad}`);
  const secret = fs.readFileSync(keyFile, "utf8"), manifest = JSON.stringify(m);
  const file = { manifest, sig: hybrid.sign(secret, "sites", manifest) };
  const root = hybrid.publicKeyOf(secret), p = sitesProblem(file, root); if (p) die(`self-check failed: ${p}`);
  fs.writeFileSync(out, JSON.stringify(file) + "\n"); d.serial = m.serial; d.at = m.at; fs.writeFileSync(draftFile, JSON.stringify(d, null, 2) + "\n");
  console.log(`Signed list ${m.serial}: ${m.mirrors.length} mirrors, ${m.malicious.length} malicious. Written to ${out}. Put it in the server's data folder as sites.json.`);
} else if (cmd === "verify") {
  const f = opt("file"), root = opt("root"); if (!f || !root) die("Use: verify --file sites.json --root <root public key> [--min-serial N]");
  const p = sitesProblem(JSON.parse(fs.readFileSync(f, "utf8")), root, Number(opt("min-serial", "0")));
  if (p) die(`NOT OK: ${p}`); console.log("OK: signed by that root key.");
} else { console.log("Commands: add-mirror | add-malicious | remove | list | sign | verify   (see the top of this file)"); process.exit(cmd ? 1 : 0); }

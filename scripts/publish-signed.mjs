#!/usr/bin/env node
// One command, run on YOUR computer, that signs what the server has staged and puts it back.
//
//   node scripts/publish-signed.mjs root@your.server [--dir zesuro-root] [--remote /root/zesuro-out] [--sites sites-draft.json]
//
// It copies release-draft.json from the server, signs it with your root key, and copies release.json back.
// If you have a sites-draft.json next to you (made with sites.mjs), it signs that too and uploads sites.json.
// The target can also be a plain folder, which is how the tests run it without a server.
// The private key never leaves your computer.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const argv = process.argv.slice(2);
const target = argv.find((a, i) => !a.startsWith("--") && !(i > 0 && argv[i - 1].startsWith("--")));
const opt = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
const die = (m) => { console.error(m); process.exit(1); };
if (!target) die("Use: node scripts/publish-signed.mjs <user@server | folder> [--dir zesuro-root] [--remote /root/zesuro-out] [--sites sites-draft.json]");
const dir = path.resolve(opt("dir", "zesuro-root")), remote = opt("remote", "/root/zesuro-out");
if (!fs.existsSync(path.join(dir, "root-key.json"))) die(`No root key in ${dir}. Run this from the folder that holds zesuro-root, or pass --dir.`);
const isHost = /@|:/.test(target) && !fs.existsSync(target);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zesuro-sign-"));
process.on("exit", () => fs.rmSync(tmp, { recursive: true, force: true }));

function get(name, to, optional = false) {
  if (!isHost) { if (optional && !fs.existsSync(path.join(target, name))) return false; fs.copyFileSync(path.join(target, name), to); return true; }
  const r = spawnSync("scp", ["-q", `${target}:${remote}/${name}`, to], { stdio: optional ? "ignore" : "inherit" });
  if (r.status !== 0) { if (optional) return false; die(`Could not fetch ${name} from ${target}`); }
  return true;
}
function put(from, name) {
  if (!isHost) return fs.copyFileSync(from, path.join(target, name));
  const r = spawnSync("scp", ["-q", from, `${target}:${remote}/${name}`], { stdio: "inherit" });
  if (r.status !== 0) die(`Could not upload ${name} to ${target}`);
}
function run(script, args) {
  const r = spawnSync(process.execPath, ["--no-warnings", path.join(import.meta.dirname, script), ...args], { stdio: "inherit" });
  if (r.status !== 0) die(`${script} failed`);
}

const draft = path.join(tmp, "release-draft.json"), out = path.join(tmp, "release.json");
get("release-draft.json", draft);
const j = JSON.parse(fs.readFileSync(draft, "utf8"));
console.log(`Release draft: ${Object.keys(j.files ?? {}).length} files${j.commit ? `, commit ${String(j.commit).slice(0, 12)}` : ""}. Signing (about 35 seconds)...`);
run("release.mjs", ["sign", "--draft", draft, "--dir", dir, "--out", out]);
put(out, "release.json");
console.log("release.json is on the server.");

const sitesDraft = path.resolve(opt("sites", "sites-draft.json"));
if (fs.existsSync(sitesDraft)) {
  const sitesOut = path.join(tmp, "sites.json");
  get("sites.json", sitesOut, true); // an earlier list, if any, so the serial number goes up
  run("sites.mjs", ["sign", "--dir", dir, "--out", sitesOut, "--draft", sitesDraft]);
  put(sitesOut, "sites.json");
  console.log("sites.json is on the server.");
}
console.log("Done. Tell Claude to deploy.");

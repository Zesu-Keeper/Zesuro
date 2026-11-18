#!/usr/bin/env node
// Vets an npm package BEFORE it is installed: is it a slopsquat / typosquat / hijack risk?
//
//   node scripts/vet-package.mjs <name>[@version] [--json]
//
// It never installs anything and never runs package code. It reads registry metadata, downloads the
// tarball into a throw-away folder (checking it against the registry's hash), scans the files, and
// resolves the full dependency tree into a lockfile only (--package-lock-only --ignore-scripts).
// Exit code: 0 = nothing found, 1 = warnings (read them), 2 = do not install.
//
// What it cannot do: prove a package is safe. A real attacker can register a hallucinated name
// first and make it look established. Treat "0 flags" as "no red flags found", then pin the exact
// version, keep the lockfile's integrity hashes, and install with --ignore-scripts.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const VERSION = /^[0-9A-Za-z.+-]+$/;
const DAY = 86_400_000;

// Names an attacker is most likely to imitate. Not exhaustive: the project's own dependencies are added too.
const POPULAR = ["react", "react-dom", "next", "express", "lodash", "axios", "chalk", "commander", "debug", "dotenv", "typescript", "webpack", "eslint", "prettier",
  "jest", "mocha", "vite", "vue", "angular", "moment", "dayjs", "uuid", "zod", "jsonwebtoken", "bcrypt", "bcryptjs", "cors", "body-parser", "cookie-parser", "mongoose",
  "sequelize", "prisma", "socket.io", "ws", "node-fetch", "request", "yargs", "inquirer", "rxjs", "tailwindcss", "postcss", "autoprefixer", "babel-core", "core-js",
  "crypto-js", "node-forge", "tweetnacl", "libsodium-wrappers", "argon2", "scrypt-js", "openpgp", "jose", "passport", "helmet", "morgan", "nodemailer", "sharp", "puppeteer",
  "@noble/curves", "@noble/hashes", "@noble/ciphers", "@noble/post-quantum", "@stablelib/chacha20poly1305", "better-sqlite3", "sqlite3", "pg", "redis", "ioredis"];

// Things a library for this job almost never needs. Each hit is a prompt to read that line, not proof.
export const PATTERNS = [
  ["runs other programs", /\b(child_process|execSync|spawnSync|execFile|spawn)\b/],
  // A bare eval( call, but not a method named eval (`x.eval(`) or its definition (`eval(a, b) {`).
  ["evaluates strings as code", /(?<![.\w])eval\s*\((?![^)\n]*\)\s*(?::[^{;\n]*)?\{)|new\s+Function\s*\(|vm\.runIn/],
  ["reads environment variables", /process\.env\b/],
  ["opens raw network sockets", /require\(\s*['"](node:)?(net|dgram|dns|tls|http2)['"]\s*\)|from\s+['"](node:)?(net|dgram|dns|tls|http2)['"]/],
  ["uses WebSocket or beacons", /\bWebSocket\b|sendBeacon/],
  ["reads or writes the file system", /require\(\s*['"](node:)?fs['"]\s*\)|from\s+['"](node:)?fs(\/promises)?['"]/],
  ["decodes hidden strings", /Buffer\.from\([^)]*,\s*['"](base64|hex)['"]\)\s*\.toString|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){7,}/i],
  ["long encoded blob", /['"`][A-Za-z0-9+/=]{400,}['"`]/],
  ["reaches for credentials or keys", /\.npmrc|\.ssh|id_rsa|AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN/],
];

/** Edit distance where swapping two neighbouring letters ("lodahs") counts as one edit, as a typo would. */
export function levenshtein(a, b) {
  if (a === b) return 0;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

/** Names that are one or two edits from a well-known one, or well-known name plus a decoration (-js, -utils, -ai ...). */
export function lookalikes(name, known) {
  const bare = name.replace(/^@[^/]+\//, "");
  const out = [];
  for (const k of known) {
    if (k === name) continue;
    const kb = k.replace(/^@[^/]+\//, "");
    const d = levenshtein(bare, kb);
    if (kb.length >= 4 && d <= (kb.length >= 8 ? 2 : 1)) out.push(`${k} (${d} edit${d === 1 ? "" : "s"} away)`);
    else if (kb.length >= 4 && bare !== kb && /^(.+?)[-_.](js|node|utils?|helpers?|ai|gpt|lib|pro|plus|secure|official|new)$/.test(bare) && bare.startsWith(kb)) out.push(`${k} plus a decoration`);
  }
  return out;
}

/** Which risky patterns appear in some source text. */
export function scanSource(text) {
  // Lines that are only a comment cannot run, so they are skipped. (Anything else on a line is scanned.)
  const code = text.split("\n").filter((l) => !/^\s*(\/\/|\*)/.test(l)).join("\n");
  return PATTERNS.filter(([, re]) => re.test(code)).map(([why]) => why);
}

/**
 * Turns the gathered facts into flags. level: "block" = do not install; "warn" = read and decide; "info".
 * Pure: takes plain data, so it can be tested without a network.
 */
export function assess(f, now = Date.now()) {
  const flags = [];
  const add = (level, msg) => flags.push({ level, msg });
  if (!f.exists) { add("block", "The registry has no such package. If an AI suggested it, it was invented: someone could register it."); return flags; }
  if (f.integrityOk === false) add("block", "The downloaded file does not match the registry's hash.");
  if (f.nonStandardSources?.length) add("block", `Dependencies fetched from outside the npm registry: ${f.nonStandardSources.join(", ")}`);
  const age = f.created ? (now - Date.parse(f.created)) / DAY : null;
  if (age !== null && age < 30) add("warn", `The package is only ${Math.floor(age)} days old.`);
  const since = f.versionTime ? (now - Date.parse(f.versionTime)) / DAY : null;
  if (since !== null && since < 3) add("warn", `This version was published ${since < 1 ? "today" : Math.floor(since) + " days ago"}: new releases are where hijacks show up. Consider the one before it.`);
  if (since !== null && since > 730) add("info", `Last release was ${Math.floor(since / 365)} years ago: unmaintained, so nobody is likely to fix a bug.`);
  if (typeof f.downloadsMonth === "number" && f.downloadsMonth < 1000) add("warn", `Only ${f.downloadsMonth} downloads in the last month.`);
  if (f.versionCount !== undefined && f.versionCount <= 2) add("warn", `Only ${f.versionCount} version(s) ever published.`);
  if (!f.repository) add("warn", "The registry lists no source repository, so the code cannot be compared with its source.");
  if (f.github?.archived) add("warn", "The GitHub repository is archived.");
  if (f.github?.missing) add("warn", "The repository the registry points to does not exist.");
  if (f.github && f.gitHead && f.github.headFound === false) add("warn", "The commit the registry says this was built from is not in the repository.");
  if (f.lifecycle?.length) add("warn", `Runs code at install time: ${f.lifecycle.join(", ")}.`);
  if (f.hasBin) add("info", "Installs command-line programs.");
  if (f.maintainers?.length === 1) add("info", "One maintainer account.");
  if (f.publisher === "GitHub Actions") add("info", "Published by GitHub Actions (automated publishing from the repository, not a person's account).");
  else if (f.publisher && f.maintainers?.length && !f.maintainers.includes(f.publisher))
    add("warn", `This version was published by "${f.publisher}", who is no longer an owner. Owners now: ${f.maintainers.join(", ")}. Look at why (a team handover is common; an account takeover looks the same from here), and be careful with newer versions.`);
  if (f.treeInstallScripts?.length) add("warn", `Dependencies that run install scripts: ${f.treeInstallScripts.join(", ")}.`);
  for (const w of f.scan || []) add("warn", `Source ${w}${f.scanFiles?.[w] ? ` (${f.scanFiles[w].slice(0, 3).join(", ")})` : ""}.`);
  if (f.audit && (f.audit.high || f.audit.critical)) add("warn", `npm audit: ${f.audit.critical || 0} critical, ${f.audit.high || 0} high vulnerabilities.`);
  for (const l of f.lookalikes || []) add("warn", `The name resembles ${l}.`);
  return flags;
}

export const exitCodeFor = (flags) => (flags.some((x) => x.level === "block") ? 2 : flags.some((x) => x.level === "warn") ? 1 : 0);

// ---------------------------------------------------------------------------------------------

async function getJson(url) {
  const r = await fetch(url, { headers: { accept: "application/json", "user-agent": "zesuro-vet-package" } });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`${url} answered ${r.status}`);
  return r.json();
}
const sh = (cmd, args, opts = {}) => execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 120_000, ...opts });

function* walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) yield* walk(p);
    else if (e.isFile()) yield p;
  }
}

export async function gather(spec, projectDir = process.cwd()) {
  const at = spec.lastIndexOf("@");
  const name = at > 0 ? spec.slice(0, at) : spec;
  const want = at > 0 ? spec.slice(at + 1) : "latest";
  if (!NAME.test(name) || name.length > 214) throw new Error("That is not a valid npm package name.");
  if (!VERSION.test(want)) throw new Error("That is not a valid version.");
  const f = { name, exists: false };
  const doc = await getJson(`https://registry.npmjs.org/${name.replace("/", "%2f")}`);
  if (!doc) return f;
  f.exists = true;
  const version = doc["dist-tags"]?.[want] || (doc.versions?.[want] ? want : null);
  if (!version) throw new Error(`No version or tag "${want}". Versions: ${Object.keys(doc.versions || {}).slice(-8).join(", ")}`);
  const v = doc.versions[version];
  Object.assign(f, {
    version,
    created: doc.time?.created, versionTime: doc.time?.[version], versionCount: Object.keys(doc.versions).length,
    maintainers: (doc.maintainers || []).map((m) => m.name),
    publisher: v._npmUser?.name || null,
    repository: typeof v.repository === "string" ? v.repository : v.repository?.url || null,
    license: typeof v.license === "string" ? v.license : null,
    gitHead: v.gitHead || null,
    lifecycle: ["preinstall", "install", "postinstall"].filter((s) => v.scripts?.[s]),
    hasBin: Boolean(v.bin && (typeof v.bin === "string" || Object.keys(v.bin).length)),
    deps: Object.keys(v.dependencies || {}),
  });
  const dl = await getJson(`https://api.npmjs.org/downloads/point/last-month/${name.replace("/", "%2f")}`).catch(() => null);
  f.downloadsMonth = typeof dl?.downloads === "number" ? dl.downloads : null;

  const gh = /github\.com[/:]([^/]+)\/([^/.]+)/.exec(f.repository || "");
  if (gh) {
    const repo = await getJson(`https://api.github.com/repos/${gh[1]}/${gh[2]}`).catch(() => undefined);
    if (repo === null) f.github = { missing: true };
    else if (repo) {
      f.github = { archived: Boolean(repo.archived), stars: repo.stargazers_count, pushedAt: repo.pushed_at, owner: repo.owner?.login };
      if (f.gitHead) f.github.headFound = (await getJson(`https://api.github.com/repos/${gh[1]}/${gh[2]}/commits/${f.gitHead}`).catch(() => undefined)) ? true : false;
    }
  }

  const work = fs.mkdtempSync(path.join(os.tmpdir(), "vet-"));
  try {
    // Tarball: hash must match the registry, then it is only ever read as text.
    const tgz = path.join(work, "pkg.tgz");
    const res = await fetch(v.dist.tarball, { headers: { "user-agent": "zesuro-vet-package" } });
    if (!res.ok) throw new Error(`tarball answered ${res.status}`);
    const bytes = Buffer.from(await res.arrayBuffer());
    fs.writeFileSync(tgz, bytes);
    const [algo, b64] = String(v.dist.integrity || "").split("-");
    f.integrityOk = algo && b64 ? createHash(algo).update(bytes).digest("base64") === b64 : undefined;
    const out = path.join(work, "x");
    fs.mkdirSync(out);
    sh("tar", ["xzf", tgz, "-C", out, "--no-same-owner", "--no-same-permissions"]);
    const seen = new Map();
    for (const file of walk(out)) {
      if (!/\.(c?js|mjs|ts|json|sh)$/.test(file) || /\.d\.ts$/.test(file) || fs.statSync(file).size > 3_000_000) continue;
      for (const why of scanSource(fs.readFileSync(file, "utf8"))) seen.set(why, [...(seen.get(why) || []), path.relative(out, file)]);
    }
    f.scan = [...seen.keys()];
    f.scanFiles = Object.fromEntries(seen);

    // Dependency tree: a lockfile only. Nothing is downloaded or run.
    const probe = path.join(work, "probe");
    fs.mkdirSync(probe);
    fs.writeFileSync(path.join(probe, "package.json"), '{"name":"probe","version":"1.0.0","private":true}');
    sh("npm", ["install", `${name}@${version}`, "--save-exact", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: probe });
    const lock = JSON.parse(fs.readFileSync(path.join(probe, "package-lock.json"), "utf8"));
    const pk = Object.entries(lock.packages).filter(([n]) => n);
    f.treeSize = pk.length;
    f.tree = pk.map(([n, p]) => `${n.replace(/^.*node_modules\//, "")}@${p.version}`);
    f.treeInstallScripts = pk.filter(([, p]) => p.hasInstallScript).map(([n]) => n.replace(/^.*node_modules\//, ""));
    f.nonStandardSources = pk.filter(([, p]) => p.resolved && !p.resolved.startsWith("https://registry.npmjs.org/")).map(([n, p]) => `${n.replace(/^.*node_modules\//, "")} <- ${p.resolved}`);
    try { f.audit = JSON.parse(sh("npm", ["audit", "--package-lock-only", "--json"], { cwd: probe })).metadata?.vulnerabilities; }
    catch (e) { try { f.audit = JSON.parse(e.stdout || "{}").metadata?.vulnerabilities; } catch { /* audit unavailable */ } }
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }

  const known = new Set(POPULAR);
  try { Object.keys({ ...JSON.parse(fs.readFileSync(path.join(projectDir, "package.json"), "utf8")).dependencies }).forEach((d) => known.add(d)); } catch { /* no project file */ }
  f.lookalikes = lookalikes(name, known);
  return f;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2).filter((a) => !a.startsWith("--"));
  const json = process.argv.includes("--json");
  if (args.length !== 1) { console.error("Use: node scripts/vet-package.mjs <name>[@version] [--json]"); process.exit(64); }
  let facts;
  try { facts = await gather(args[0]); } catch (e) { console.error(`Could not vet it: ${e.message}`); process.exit(64); }
  const flags = assess(facts);
  const code = exitCodeFor(flags);
  if (json) console.log(JSON.stringify({ facts, flags, exit: code }, null, 2));
  else {
    console.log(`\n${facts.name}${facts.version ? "@" + facts.version : ""}`);
    if (facts.exists) {
      console.log(`  created ${facts.created?.slice(0, 10)}, this version ${facts.versionTime?.slice(0, 10)}, ${facts.versionCount} versions, ${facts.downloadsMonth ?? "?"} downloads last month`);
      console.log(`  owners now: ${facts.maintainers.join(", ") || "none listed"}; this version published by: ${facts.publisher || "?"}; repo: ${facts.repository || "none"}${facts.github?.stars !== undefined ? ` (${facts.github.stars} stars, last push ${facts.github.pushedAt?.slice(0, 10)})` : ""}`);
      console.log(`  hash matches registry: ${facts.integrityOk}; tree: ${facts.treeSize} packages; install scripts in package: ${facts.lifecycle.length ? facts.lifecycle.join(",") : "none"}`);
      console.log(`  tree: ${facts.tree.join(" ")}`);
    }
    console.log(flags.length ? "\nFlags:" : "\nNo flags.");
    for (const x of flags) console.log(`  [${x.level.toUpperCase()}] ${x.msg}`);
    console.log(`\n${code === 2 ? "DO NOT INSTALL." : code === 1 ? "Read the warnings before deciding." : "No red flags found. That is not proof of safety: pin the exact version and use --ignore-scripts."}`);
  }
  process.exit(code);
}

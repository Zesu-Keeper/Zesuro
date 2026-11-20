#!/usr/bin/env node
// A Zesuro mirror: keeps its own complete copy of the public record, re-verifies every hash as
// it copies, and raises an alarm if any server (including the original) ever rewrites, drops or
// forks history. Needs only Node 22 and no packages.
//
//   node scripts/mirror.mjs <source> [options]
//
//   <source>            a Zesuro site or another mirror, e.g. https://zesuro.com
//   --dir <folder>      where the copy lives (default ./zesuro-mirror)
//   --peer <url>        another site or mirror to compare with (repeatable)
//   --serve <port>      also serve the copy, read-only, so others can mirror from you
//   --watch <seconds>   keep running, syncing every so often (default: sync once and exit)
//   --full              also re-download everything held and compare it line by line (slower)
//   --witness           countersign each of the site's signed anchors that this copy confirms
//   --standby           also keep the site's latest encrypted snapshot (in <dir>/snapshots), checked
//                       against the signed manifest, so this machine can take over if the site is lost.
//                       The site hands snapshots only to standbys whose key the operator accepted: the
//                       key is this mirror's witness key (printed on first run). The snapshot is
//                       encrypted to the recovery key, which this mirror never has.
//   --check-code        (needs --root) each round, also fetch the site's pages and compare every script
//                       and stylesheet with the release list the root key signed (scripts/release.mjs).
//                       An altered or unsigned script raises an ALERT. A server can still treat a
//                       targeted visitor differently from a checker, so run this from several places.
//   --public-url <addr> the https address this mirror is served at. With --serve, a mirror may only serve
//                       the record if the root key's signed list (/api/sites) names this address as a mirror.
//   --root <key>        the record's root public key (zs1.…), which you get from the operator
//                       out of band. Pinned on first use and never changed afterwards. With it,
//                       this mirror accepts a signed tip only from the server the root key has
//                       delegated that part of the record to (see scripts/root.mjs), and it keeps
//                       the site's authority file and refuses any that rewrites what it holds.
//                       Without it the site's own published key is trusted on first use, which
//                       means a seized or replaced server can sign as itself.
//
// What a mirror checks, every time:
//   - each new entry and comment is well formed and extends the chain: its hash is what its
//     contents give, and it follows the last one this mirror already holds
//   - the entry and comment this mirror held last are still, byte for byte, what the source
//     serves (a server can't swap history without this showing)
//   - the site's signed anchors: signed by the writer the root key delegated to (with --root) or
//     else by the site's key pinned the first time this mirror meets it, and their tips match
//     this mirror's own chains
//   - each peer's chains agree with this mirror's, as far as both reach
// As a witness (--witness) it also signs every anchor it has confirmed, with the time it saw it,
// and sends the signature to the site. The mirror makes its own key on first run and prints it;
// send that key to the site's operator, who decides whether to accept you as a witness. A
// witness never signs an anchor its own copy disagrees with or can't yet check in full.
// On a problem it prints ALERT, writes evidence to <dir>/alerts/ and exits with status 2.
// It never overwrites what it already holds with something that disagrees.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { ZERO, anchorSigner, snapshotSigner, authorityExtends, authorityProblem, commentHash, commentProblem, currentWriter, entryHash, entryProblem, isWriterKey } from "./log-core.mjs";
import { isHybridKey } from "./hybrid-sig.mjs";
import { checkCode } from "./code-check.mjs";
import { appendOnlyProblems, fetchLog, logProblems } from "./release-log-core.mjs";
import { classify, sitesProblem } from "./sites-core.mjs";

// ---------------------------------------------------------------- options
const argv = process.argv.slice(2);
const opts = { dir: "zesuro-mirror", peers: [], serve: 0, watch: 0, source: "", full: false, witness: false, root: "", standby: false, checkCode: false, publicUrl: "" };
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === "--dir") opts.dir = argv[++i];
  else if (a === "--peer") opts.peers.push(argv[++i]);
  else if (a === "--serve") opts.serve = Number(argv[++i]);
  else if (a === "--watch") opts.watch = Number(argv[++i]);
  else if (a === "--full") opts.full = true;
  else if (a === "--witness") opts.witness = true;
  else if (a === "--root") opts.root = argv[++i] ?? "";
  else if (a === "--public-url") opts.publicUrl = argv[++i] ?? "";
  else if (a === "--standby") opts.standby = true;
  else if (a === "--check-code") opts.checkCode = true;
  else if (!a.startsWith("--") && !opts.source) opts.source = a;
  else usage();
}
function usage() {
  console.error("Usage: node scripts/mirror.mjs <source> [--dir folder] [--peer url]... [--serve port] [--watch seconds] [--full] [--witness] [--root <root key>] [--standby] [--check-code] [--public-url <https address>]");
  process.exit(64);
}
const clean = (u) => String(u || "").replace(/\/+$/, "");
opts.source = clean(opts.source);
opts.peers = opts.peers.map(clean);
if (!/^https?:\/\//.test(opts.source) || opts.peers.some((p) => !/^https?:\/\//.test(p))) usage();
if (opts.checkCode && !opts.root) { console.error("--check-code needs --root"); process.exit(64); }
if (opts.root && !isHybridKey(opts.root)) { console.error("--root must be the root public key (it starts with zs1.)"); process.exit(64); }
if (!Number.isInteger(opts.serve) || opts.serve < 0 || opts.serve > 65535 || !Number.isFinite(opts.watch) || opts.watch < 0) usage();

// ---------------------------------------------------------------- local copy
const dir = path.resolve(opts.dir);
for (const d of ["", "alerts"]) fs.mkdirSync(path.join(dir, d), { recursive: true });
const F = { entries: path.join(dir, "entries.jsonl"), comments: path.join(dir, "comments.jsonl"), anchors: path.join(dir, "anchors.jsonl"), state: path.join(dir, "state.json"), authority: path.join(dir, "authority.json") };
const readLines = (f) => (fs.existsSync(f) ? fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const state = fs.existsSync(F.state) ? JSON.parse(fs.readFileSync(F.state, "utf8")) : { siteKey: null };
const saveState = () => fs.writeFileSync(F.state, JSON.stringify(state, null, 2));
state.witnessed ??= {}; // anchor id -> { at, sig }: what this mirror has signed
// The root key is pinned once. A different one later is refused, not adopted.
if (opts.root) {
  if (state.root && state.root !== opts.root) { console.error(`This mirror is pinned to root key ${state.root}; refusing ${opts.root}. Use a new folder to follow a different record.`); process.exit(64); }
  if (!state.root) { state.root = opts.root; saveState(); console.log(`Pinned the root key: ${state.root}`); }
}
let authority = fs.existsSync(F.authority) ? JSON.parse(fs.readFileSync(F.authority, "utf8")) : null;

// This mirror's own signing key, used only with --witness.
let witnessKey = null, witnessPub = null;
if (opts.witness || opts.standby) {
  const kf = path.join(dir, "witness-key.pem");
  if (!fs.existsSync(kf)) fs.writeFileSync(kf, generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  witnessKey = createPrivateKey(fs.readFileSync(kf));
  witnessPub = createPublicKey(witnessKey).export({ format: "jwk" }).x;
  console.log(`Witness key: ${witnessPub}\n  Send this key to the site's operator. Until they accept it, signatures are kept here but not shown by the site.`);
}
const witnessMessage = (head, at) => `zesuro:witness:v1:${createHash("sha256").update(head).digest("hex")}:${at}`;

const entries = readLines(F.entries);
const comments = readLines(F.comments);
const anchors = readLines(F.anchors); // { id, at, head (exact text), sig }
const entryTip = (n) => (n === 0 ? ZERO : entries[n - 1].entryHash);
const commentTip = (n) => (n === 0 ? ZERO : comments[n - 1].commentHash);

let alerts = 0;
function alert(source, kind, detail) {
  alerts++;
  const evidence = { at: new Date().toISOString(), source, kind, detail, held: { entries: entries.length, entryTip: entryTip(entries.length), comments: comments.length, commentTip: commentTip(comments.length) } };
  const file = path.join(dir, "alerts", `${evidence.at.replace(/[:.]/g, "-")}-${kind}.json`);
  fs.writeFileSync(file, JSON.stringify(evidence, null, 2));
  console.log(`ALERT  [${kind}] ${source}: ${detail}\n       evidence saved to ${file}`);
}

// The copy on disk must itself be intact before anything is added to it.
function checkOwnCopy() {
  let prev = ZERO;
  for (const [i, x] of entries.entries()) {
    if (entryProblem(x) || x.seq !== i + 1 || x.prevHash !== prev || entryHash(prev, x) !== x.entryHash) { alert("local copy", "local-corrupt", `entry ${i + 1} in ${F.entries} does not verify`); return false; }
    prev = x.entryHash;
  }
  prev = ZERO;
  for (const [i, x] of comments.entries()) {
    if (commentProblem(x) || x.id < 1 || x.prevHash !== prev || commentHash(prev, x) !== x.commentHash) { alert("local copy", "local-corrupt", `comment line ${i + 1} in ${F.comments} does not verify`); return false; }
    prev = x.commentHash;
  }
  return true;
}

// ---------------------------------------------------------------- talking to a source
async function getJson(base, p) {
  const r = await fetch(base + p, { signal: AbortSignal.timeout(20_000), headers: { accept: "application/json" } });
  if (!r.ok) throw new Error(`${base}${p}: HTTP ${r.status}`);
  return r.json();
}
async function getBytes(base, p, max) {
  const r = await fetch(base + p, { signal: AbortSignal.timeout(20_000) });
  if (!r.ok) throw new Error(`${base}${p}: HTTP ${r.status}`);
  const b = Buffer.from(await r.arrayBuffer());
  if (b.length > max) throw new Error(`${base}${p}: too large`);
  return b;
}

const canon = (o) => JSON.stringify(Object.fromEntries(Object.entries(o).sort(([a], [b]) => (a < b ? -1 : 1))));

/** Re-downloads everything held and compares it with the local copy, line by line. */
async function fullCheck(base) {
  for (let i = 0; i < entries.length; i += 500) {
    const page = (await getJson(base, `/api/log?after=${i}&limit=500`)).entries ?? [];
    for (const [j, x] of page.entries()) {
      if (i + j >= entries.length) break;
      if (canon(x) !== canon(entries[i + j])) { alert(base, "history-rewritten", `entry ${i + j + 1} is not what this mirror recorded`); return false; }
    }
    if (page.length < Math.min(500, entries.length - i)) { alert(base, "history-shrank", `serves fewer entries than this mirror holds`); return false; }
  }
  for (let i = 0; i < comments.length; i += 500) {
    const after = i === 0 ? 0 : comments[i - 1].id;
    const page = (await getJson(base, `/api/log/comments?after=${after}&limit=500`)).comments ?? [];
    for (const [j, x] of page.entries()) {
      if (i + j >= comments.length) break;
      if (canon(x) !== canon(comments[i + j])) { alert(base, "history-rewritten", `comment ${comments[i + j].id} is not what this mirror recorded`); return false; }
    }
    if (page.length < Math.min(500, comments.length - i)) { alert(base, "history-shrank", `serves fewer comments than this mirror holds`); return false; }
  }
  return true;
}

/** Brings the copy up to date from `base`. Returns false if the source can't be trusted this round. */
async function sync(base) {
  // 1. Entries. First: is the entry we hold last still what the source says it is?
  let n = entries.length;
  if (n > 0) {
    const r = (await getJson(base, `/api/log?after=${n - 1}&limit=1`)).entries ?? [];
    if (!r[0]) { alert(base, "history-shrank", `holds ${n} entries here but serves fewer`); return false; }
    if (r[0].entryHash !== entries[n - 1].entryHash || r[0].seq !== n) { alert(base, "history-rewritten", `entry ${n} is not what this mirror recorded: it was ${entries[n - 1].entryHash}, the source now serves ${r[0].entryHash}`); return false; }
  }
  for (;;) {
    const page = (await getJson(base, `/api/log?after=${entries.length}&limit=500`)).entries ?? [];
    if (!page.length) break;
    const fresh = [];
    let prev = entryTip(entries.length);
    for (const x of page) {
      const bad = entryProblem(x);
      if (bad || x.seq !== entries.length + fresh.length + 1 || x.prevHash !== prev || entryHash(prev, x) !== x.entryHash) {
        alert(base, "bad-entry", `entry ${x?.seq} does not verify${bad ? ` (${bad})` : ""}`);
        return false;
      }
      fresh.push(x);
      prev = x.entryHash;
    }
    fs.appendFileSync(F.entries, fresh.map((x) => JSON.stringify(x) + "\n").join(""));
    entries.push(...fresh);
  }
  // 2. Comments, the same way.
  n = comments.length;
  if (n > 0) {
    const r = (await getJson(base, `/api/log/comments?after=${comments[n - 1].id - 1}&limit=1`)).comments ?? [];
    if (!r[0] || r[0].id !== comments[n - 1].id) { alert(base, "history-shrank", `holds ${n} comments here but serves fewer`); return false; }
    if (r[0].commentHash !== comments[n - 1].commentHash) { alert(base, "history-rewritten", `comment ${r[0].id} is not what this mirror recorded`); return false; }
  }
  for (;;) {
    const after = comments.length ? comments[comments.length - 1].id : 0;
    const page = (await getJson(base, `/api/log/comments?after=${after}&limit=500`)).comments ?? [];
    if (!page.length) break;
    const fresh = [];
    let prev = commentTip(comments.length);
    for (const x of page) {
      const bad = commentProblem(x);
      if (bad || x.id <= (fresh.length ? fresh[fresh.length - 1].id : after) || x.prevHash !== prev || commentHash(prev, x) !== x.commentHash) {
        alert(base, "bad-comment", `comment ${x?.id} does not verify${bad ? ` (${bad})` : ""}`);
        return false;
      }
      fresh.push(x);
      prev = x.commentHash;
    }
    fs.appendFileSync(F.comments, fresh.map((x) => JSON.stringify(x) + "\n").join(""));
    comments.push(...fresh);
  }
  // 3. Optionally, everything held again, line by line.
  if (opts.full && !(await fullCheck(base))) return false;
  // 4. Anchors.
  return syncAnchors(base);
}

/** Fetches the site's authority file and keeps it if it checks out against the pinned root and continues what is held. */
async function syncAuthority(base) {
  let got = null;
  try { got = await getJson(base, "/api/authority"); } catch { /* the source may not publish one; the copy held is used */ }
  if (got) {
    const bad = authorityProblem(got, state.root);
    if (bad) { alert(base, "bad-authority", `the authority file it serves is not valid: ${bad}`); return false; }
    if (!authorityExtends(authority, got)) { alert(base, "authority-rewritten", "the authority file it serves does not continue the one this mirror holds (a delegation was removed or changed)"); return false; }
    if (!authority || got.delegations.length > authority.delegations.length) {
      authority = got;
      fs.writeFileSync(F.authority, JSON.stringify(got, null, 2) + "\n");
      console.log(`Authority updated: ${got.delegations.length} delegation(s). Current writer ${currentWriter(got)}`);
    }
  }
  if (!authority) { alert(base, "no-authority", "a root key is pinned but no authority file has been published, so no signed tip can be accepted"); return false; }
  return true;
}

/** Checks one anchor against the pinned key and this mirror's own chains. Returns a problem or null. */
function anchorProblem(headText, sig) {
  let h;
  try { h = JSON.parse(headText); } catch { return "its signed text is not JSON"; }
  const signer = anchorSigner({ auth: state.root ? authority : null, siteKey: state.siteKey }, headText, sig);
  if (!signer) return state.root ? "it is not signed by the server the root key has delegated this part of the record to" : "its signature is not the site's";
  const ec = h?.entries?.count, cc = h?.comments?.count;
  if (!Number.isSafeInteger(ec) || !Number.isSafeInteger(cc)) return "its counts are malformed";
  if (ec > entries.length || cc > comments.length) return null; // reaches past this copy: can't be checked yet
  if (entryTip(ec) !== h.entries.tip || commentTip(cc) !== h.comments.tip) return "the tips it signed are not the tips of the record (history differs from what was signed)";
  return null;
}

async function syncAnchors(base) {
  if (state.root && !(await syncAuthority(base))) return false;
  const known = new Set(anchors.map((a) => a.id));
  const listing = [];
  for (let before = 0, guard = 0; guard < 50; guard++) {
    const r = await getJson(base, `/api/anchors?limit=200${before ? `&before=${before}` : ""}`);
    if (typeof r.publicKey !== "string" || !isWriterKey(r.publicKey)) { if (!(r.anchors ?? []).length) return true; alert(base, "bad-anchor", "no valid site key published"); return false; }
    if (!state.siteKey) { state.siteKey = r.publicKey; saveState(); console.log(`Pinned the site's signing key: ${r.publicKey}`); }
    else if (state.siteKey !== r.publicKey) {
      // With a root key, a change of signing key is fine if the root delegated to the new one; otherwise it is an alarm.
      if (!(state.root && authority && currentWriter(authority) === r.publicKey)) { alert(base, "key-changed", `the site now signs with ${r.publicKey}, not the key pinned here (${state.siteKey})`); return false; }
      state.siteKey = r.publicKey; saveState();
    }
    if (state.root && currentWriter(authority) !== r.publicKey) { alert(base, "not-delegated", `the site signs with ${r.publicKey}, which the root key has not delegated to (the current writer is ${currentWriter(authority)})`); return false; }
    const rows = r.anchors ?? [];
    listing.push(...rows);
    if (rows.length < 200 || rows.some((a) => known.has(a.id))) break;
    before = rows[rows.length - 1].id;
  }
  for (const a of listing.filter((x) => !known.has(x.id)).sort((x, y) => x.id - y.id)) {
    const head = (await getBytes(base, `/api/anchors/${a.id}/head`, 4096)).toString("utf8");
    const bad = anchorProblem(head, a.sig);
    if (bad) { alert(base, "bad-anchor", `anchor ${a.id}: ${bad}`); return false; }
    const rec = { id: a.id, at: a.at, head, sig: a.sig };
    fs.appendFileSync(F.anchors, JSON.stringify(rec) + "\n");
    anchors.push(rec);
  }
  // Anchors held earlier are checked again against the (possibly longer) chains every round.
  for (const a of anchors) { const bad = anchorProblem(a.head, a.sig); if (bad) { alert(base, "bad-anchor", `anchor ${a.id}: ${bad}`); return false; } }
  if (opts.witness) await witnessAnchors(base);
  if (opts.standby && !(await syncSnapshot(base))) return false;
  return true;
}

/** Keeps the site's latest snapshot if its manifest is signed by the rightful writer and its hash matches. */
async function syncSnapshot(base) {
  let latest;
  try { latest = await getJson(base, "/api/snapshot/latest"); }
  catch (e) { console.log(`  snapshot: none available (${e.message})`); return true; }
  const text = String(latest?.manifest ?? "");
  const writer = snapshotSigner({ auth: state.root ? authority : null, siteKey: state.siteKey }, text, latest?.sig);
  if (!writer) { alert(base, "bad-snapshot", "the latest snapshot's manifest is not signed by the server entitled to write the record"); return false; }
  const m = JSON.parse(text);
  const sdir = path.join(dir, "snapshots");
  fs.mkdirSync(sdir, { recursive: true });
  const target = path.join(sdir, m.name);
  if (!/^snapshot-\d{10,16}\.zsnap$/.test(String(m.name))) { alert(base, "bad-snapshot", "its name is not a snapshot file name"); return false; }
  if (fs.existsSync(target)) return true;
  if (!Number.isSafeInteger(m.size) || m.size > 1_000_000_000) { alert(base, "bad-snapshot", "its size is not acceptable"); return false; }
  // Ask for the file with a signature from this mirror's key; the site checks that it accepted the key.
  const at = Date.now();
  const sig = sign(null, Buffer.from(`zesuro:snapshot-get:v1:${m.name}:${at}`), witnessKey).toString("base64url");
  const r = await fetch(`${base}/api/snapshot/${m.name}`, { headers: { "x-zesuro-key": witnessPub, "x-zesuro-at": String(at), "x-zesuro-sig": sig }, signal: AbortSignal.timeout(300_000) });
  if (r.status === 401) { console.log("  snapshot: not downloaded; the site has not accepted this mirror's key as a standby yet"); return true; }
  if (!r.ok) { console.log(`  snapshot: the site answered ${r.status}`); return true; }
  const bytes = Buffer.from(await r.arrayBuffer());
  if (bytes.length !== m.size || createHash("sha256").update(bytes).digest("hex") !== m.sha256) { alert(base, "bad-snapshot", "the snapshot file is not the one its signed manifest describes"); return false; }
  fs.writeFileSync(target + ".part", bytes, { mode: 0o600 });
  fs.renameSync(target + ".part", target);
  fs.writeFileSync(path.join(sdir, "latest.json"), JSON.stringify(latest), { mode: 0o600 });
  for (const old of fs.readdirSync(sdir).filter((f) => f.endsWith(".zsnap")).sort().slice(0, -3)) fs.rmSync(path.join(sdir, old), { force: true });
  console.log(`  snapshot kept: ${m.name} (${m.entries.count} entries, ${m.comments.count} comments)`);
  return true;
}

/** Signs each anchor this copy fully confirms, once, and hands the signatures to the site. */
async function witnessAnchors(base) {
  let sent = 0, refused = null;
  for (const a of anchors) {
    const h = JSON.parse(a.head);
    // Only what this copy reaches and agrees with. (anchorProblem already passed for all of them.)
    if (h.entries.count > entries.length || h.comments.count > comments.length) continue;
    let w = state.witnessed[a.id];
    if (!w) {
      const at = Date.now();
      w = state.witnessed[a.id] = { at, sig: sign(null, Buffer.from(witnessMessage(a.head, at)), witnessKey).toString("base64url"), sent: false };
      saveState();
    }
    if (w.sent) continue;
    try {
      const r = await fetch(`${base}/api/anchors/${a.id}/witness`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ key: witnessPub, at: w.at, sig: w.sig }), signal: AbortSignal.timeout(20_000) });
      if (r.ok) { w.sent = true; sent++; saveState(); }
      else if (r.status === 403) { refused = "the site has not accepted this witness key yet"; break; }
      else if (r.status === 404 || r.status === 405) { refused = "this source does not take witness signatures (it may be a mirror)"; break; }
      else { refused = `the site answered ${r.status}`; break; }
    } catch (e) { refused = e.message; break; }
  }
  if (sent) console.log(`  witnessed ${sent} anchor(s)`);
  if (refused) console.log(`  witness signatures not delivered: ${refused}`);
}

/** Compares a peer's chains with ours, as far as both reach. Returns true if they agree. */
async function crossCheck(peer) {
  const c = await getJson(peer, "/api/chain");
  const pe = c?.count, pc = c?.comments?.count;
  if (!Number.isSafeInteger(pe) || !Number.isSafeInteger(pc)) { alert(peer, "peer-bad", "its /api/chain answer is malformed"); return false; }
  const n = Math.min(pe, entries.length);
  if (n > 0) {
    const r = (await getJson(peer, `/api/log?after=${n - 1}&limit=1`)).entries ?? [];
    if (!r[0] || r[0].entryHash !== entries[n - 1].entryHash) { alert(peer, "fork", `at entry ${n} this peer's record differs from this mirror's`); return false; }
  }
  const m = Math.min(pc, comments.length);
  if (m > 0) {
    const r = (await getJson(peer, `/api/log/comments?after=${comments[m - 1].id - 1}&limit=1`)).comments ?? [];
    if (!r[0] || r[0].commentHash !== comments[m - 1].commentHash) { alert(peer, "fork", `at comment ${m} this peer's record differs from this mirror's`); return false; }
  }
  const lag = (pe < entries.length || pc < comments.length) ? "behind" : (pe > entries.length || pc > comments.length) ? "ahead of" : "level with";
  console.log(`  peer ${peer}: agrees (${pe} entries, ${pc} comments; ${lag} this mirror)`);
  return true;
}

// ---------------------------------------------------------------- serving the copy
function serve(port) {
  const hits = new Map();
  const server = http.createServer((req, res) => {
    const send = (code, body, type = "application/json; charset=utf-8") => { res.writeHead(code, { "content-type": type, "cache-control": "no-store", "x-content-type-options": "nosniff" }); res.end(body); };
    const now = Date.now(), who = req.socket.remoteAddress ?? "";
    const recent = (hits.get(who) ?? []).filter((t) => now - t < 60_000);
    if (recent.length >= 120) return send(429, '{"error":"Slow down a moment"}');
    recent.push(now); hits.set(who, recent);
    if (hits.size > 5000) for (const k of hits.keys()) { hits.delete(k); if (hits.size < 4000) break; }
    if (req.method !== "GET") return send(405, '{"error":"Read only"}');
    const u = new URL(req.url, "http://x");
    const num = (k, d) => { const v = Number(u.searchParams.get(k) ?? d); return Number.isSafeInteger(v) && v >= 0 ? v : d; };
    const limit = Math.min(Math.max(num("limit", 500), 1), 1000);
    let m;
    if (u.pathname === "/api/log") return send(200, JSON.stringify({ entries: entries.slice(num("after", 0), num("after", 0) + limit) }));
    if (u.pathname === "/api/log/comments") { const after = num("after", 0); return send(200, JSON.stringify({ comments: comments.filter((c) => c.id > after).slice(0, limit) })); }
    if (u.pathname === "/api/chain") return send(200, JSON.stringify({ ok: true, count: entries.length, tip: entryTip(entries.length), comments: { ok: true, count: comments.length, tip: commentTip(comments.length) }, mirror: true }));
    if (u.pathname === "/api/authority") return authority ? send(200, JSON.stringify(authority)) : send(404, '{"error":"No authority has been published"}');
    if (u.pathname === "/api/anchors") {
      const before = num("before", 0) || Infinity;
      const rows = anchors.filter((a) => a.id < before).sort((a, b) => b.id - a.id).slice(0, Math.min(limit, 200));
      // A mirror passes on the site's anchors with its own countersignature, if it is a witness.
      return send(200, JSON.stringify({ publicKey: state.siteKey, anchors: rows.map((a) => ({ id: a.id, at: a.at, head: JSON.parse(a.head), sig: a.sig, witnesses: witnessPub && state.witnessed[a.id] ? [{ key: witnessPub, name: "this mirror", at: state.witnessed[a.id].at, sig: state.witnessed[a.id].sig }] : [] })) }));
    }
    if ((m = /^\/api\/anchors\/(\d{1,12})\/head$/.exec(u.pathname))) { const a = anchors.find((x) => x.id === Number(m[1])); return a ? send(200, a.head) : send(404, "Not found", "text/plain"); }
    send(404, '{"error":"Not found"}');
  });
  server.listen(port, () => console.log(`Serving this copy, read-only, on port ${port}. Put it behind HTTPS before sharing it.`));
  return server;
}

// ---------------------------------------------------------------- run
async function round() {
  alerts = 0;
  if (!checkOwnCopy()) return 2;
  let failed = false;
  try { if (!(await sync(opts.source))) return 2; }
  catch (e) { console.log(`Could not reach ${opts.source}: ${e.message}`); failed = true; }
  if (opts.checkCode && state.root) {
    try {
      const c = await checkCode(opts.source, state.root);
      for (const p of c.problems) alert(opts.source, "code-changed", p);
      if (!c.problems.length) console.log(`  code: all ${c.checked} scripts and stylesheets match the signed release`);
    } catch (e) { console.log(`  code check could not run: ${e.message}`); failed = true; }
  }
  // The release log: keep a copy, and complain if a release ever changes or disappears from it.
  try {
    const log = await fetchLog(opts.source);
    const file = path.join(opts.dir, "release-log.json");
    let before = [];
    try { before = JSON.parse(fs.readFileSync(file, "utf8")); } catch { /* first time */ }
    const bad = [...appendOnlyProblems(before, log.releases), ...logProblems(log.releases, state.root || "")];
    for (const p of bad) alert(opts.source, "release-log", p);
    if (!bad.length) {
      fs.writeFileSync(file, JSON.stringify(log.releases));
      console.log(`  release log: ${log.releases.length} release(s), all in order`);
    }
  } catch (e) { console.log(`  release log could not be checked: ${e.message}`); }
  for (const p of opts.peers) {
    try { await crossCheck(p); }
    catch (e) { console.log(`  peer ${p}: could not be reached (${e.message})`); failed = true; }
  }
  console.log(`Mirror holds ${entries.length} entries, ${comments.length} comments and ${anchors.length} anchors. Entry tip ${entryTip(entries.length).slice(0, 16)}…`);
  return alerts ? 2 : failed ? 1 : 0;
}

// Serving the record to others is allowed only for a site the root key has listed as a mirror.
// Copying for your own checking needs no listing.
async function mayServe() {
  try {
    const r = await fetch(opts.source.replace(/\/+$/, "") + "/api/sites", { signal: AbortSignal.timeout(15000) });
    if (!r.ok) return "the source has no signed list of mirrors";
    const file = await r.json();
    const seenFile = path.join(opts.dir, "sites-serial");
    const seen = fs.existsSync(seenFile) ? Number(fs.readFileSync(seenFile, "utf8")) || 0 : 0;
    const bad = sitesProblem(file, state.root || opts.root, seen);
    if (bad) return `the mirror list is not acceptable: ${bad}`;
    const m = JSON.parse(file.manifest);
    const kind = classify(m, { url: opts.publicUrl });
    if (kind !== "mirror") return kind === "malicious" ? "this address is listed as an impostor" : "this address is not on the root's list of mirrors";
    fs.writeFileSync(seenFile, String(m.serial));
    return null;
  } catch (e) { return `could not check the list of mirrors (${e.message})`; }
}
if (opts.serve && (!opts.root || !opts.publicUrl)) { console.error("--serve needs --root and --public-url: only a site the root key lists as a mirror may serve the record."); process.exit(64); }
if (opts.serve) {
  const no = await mayServe();
  if (no) { console.error(`Not serving: ${no}. Add this address with sites.mjs add-mirror and publish the signed list, or run without --serve.`); process.exit(3); }
}
const server = opts.serve ? serve(opts.serve) : null;
let code = await round();
if (opts.watch > 0) {
  for (;;) {
    await new Promise((r) => setTimeout(r, opts.watch * 1000));
    if (server) {
      const no = await mayServe();
      if (no && !/could not check/.test(no)) { console.error(`Stopped serving: ${no}.`); server.close(); process.exit(3); }
    }
    code = await round();
  }
}
if (server) { console.log("Press Ctrl+C to stop serving."); } else process.exit(code);

// Integration test: time-locked reveals through the real app code (sealing, the hash chain, the public
// log, the release sweep) against a temporary database. The drand relays are mocked with REAL past
// quicknet beacons, including a relay that lies. Nothing touches the network or the live site.
// Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/timelock-wire.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { ZERO, entryHash, entryProblem } from "./log-core.mjs";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tl-wire-"));
process.chdir(tmp); // the app keeps its database in ./data
const imp = (f) => import(path.join(root, "src/lib", f));
const [E, B, CC, DB, TL, RB, CM] = await Promise.all([imp("entries.ts"), imp("beacon.ts"), imp("client-crypto.ts"), imp("db.ts"), imp("timelock.ts"), imp("release-bundle.ts"), imp("commit.ts")]);

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const rejects = async (p, re, m) => { await assert.rejects(p, re, m); n++; };
const sha = (s) => createHash("sha256").update(s).digest("hex");

const SIG = {
  1000000: "83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72",
  2000000: "a7c94d62fa50475c65f259bc4d50afc0cebc5cb29848568f90dff842789c05d7f6b2414971a0b67bf532624ad6bab054",
};
const flipHex = (h) => h.slice(0, 20) + (h[20] === "0" ? "1" : "0") + h.slice(21);

// ---- an author's key, as the browser would hold it
const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
const key = {
  priv: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d, ext: true, key_ops: ["sign"] },
  pub: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true, key_ops: ["verify"] },
};

/** Builds a time-locked entry exactly as the say page does. */
let counter = 0;
async function sealLocked({ revealAt = Date.now() + 120_000, handle, mode = "date", hiddenPlace = false, revealPublic = false, lockRound } = {}) {
  const uid = crypto.randomUUID();
  const nonce = CC.randomHex(16);
  const title = `Time-locked test ${++counter}`;
  const text = `A unique thing said in test number ${counter} on ${uid}`;
  const secret = hiddenPlace ? CC.makeSecret([], { lat: 48.8584, lng: 2.2945, label: "Hidden place" }) : null;
  const secretCommit = secret ? await CC.secretCommitOf(secret) : null;
  const content = { uid, title: CM.normTitle(title), text: CM.normText(text), placeMode: hiddenPlace ? "hidden" : "none", place: null, secretCommit, mode };
  const commitment = await CC.commitmentV2(key, nonce, content);
  const opening = await CC.makeOpeningV2(key, uid, nonce, handle);
  const round = lockRound ?? TL.roundForTime(revealAt);
  const ct = TL.timelockEncrypt(RB.encodeBundle({ opening, secret }), round);
  const input = {
    uid, title: content.title, text: content.text, placeMode: content.placeMode, place: null, commitV: 2,
    secretCommit, secretBlob: secret ? "c21va2U" : undefined, commitment, nonce, mode, revealAt, deadlineAt: null,
    opening: null, secret: null, timelock: { round, ct }, revealPublic,
  };
  return { uid, nonce, opening, secret, ct, round, content, input, seal: () => E.sealEntry(input) };
}

// The chain as a stranger would check it: only log-core's formulas, only what /api/log would send.
function checkLog() {
  let prev = ZERO, count = 0;
  for (const x of E.listLog(0, 1000)) {
    if (entryProblem(x) || x.prevHash !== prev || entryHash(prev, x) !== x.entryHash) return { ok: false, at: x.seq, why: entryProblem(x) };
    prev = x.entryHash; count++;
  }
  return { ok: true, count };
}

const db = DB.getDb();
// Reading an entry through getEntry() can start the background release pass, so mid-test state is read from SQL.
const st = (uid) => db.prepare("SELECT revealed_at, handle, tl_error FROM entries WHERE uid = ?").get(uid);

// ===================================================================== sealing
const HANDLE = "Quiet Quentin 7f3a";
const a = await sealLocked({ handle: HANDLE, hiddenPlace: true });
const entry = await a.seal();
ok(entry.hashVersion === 4 && entry.timelock?.hash === sha(a.ct), "a time-locked entry is hash v4 and records the ciphertext's hash");
ok(entry.timelock.round === null && entry.revealAt === null, "a private reveal date: the round (which gives it away) is not shown");
ok(entry.status === "anonymous" && entry.handle === null && entry.opening === null && entry.secret === null, "nothing is revealed yet");

const row = db.prepare("SELECT * FROM entries WHERE uid = ?").get(a.uid);
ok(row.reveal_pkg === null && row.secret_pkg === null, "the server holds no opening and no hidden parts");
ok(row.tl_ct === a.ct && row.tl_hash === sha(a.ct) && row.tl_round === a.round, "it holds the ciphertext, its hash and round");
db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
const dbBytes = Buffer.concat(fs.readdirSync("data").filter((f) => f.startsWith("whenisaid.db")).map((f) => fs.readFileSync(path.join("data", f)))).toString("latin1");
ok(!dbBytes.includes(HANDLE) && !dbBytes.includes("Hidden place") && !dbBytes.includes(a.secret.salt), "the name and the hidden place appear nowhere in the database files");

ok(E.verifyChain().ok, "the app's own chain check passes");
let log = E.listLog(0, 10);
ok(log[0].hashV === 4 && log[0].tlHash === sha(a.ct) && log[0].tl === null, "private date: the log shows the hash but not the ciphertext");
ok(checkLog().ok, "log-core (the independent definition) agrees with the chain");

// public date: the ciphertext is published, and verifiers check it is what the chain covers
const b = await sealLocked({ handle: "Public Priya", revealPublic: true });
const entryB = await b.seal();
ok(entryB.timelock.round === b.round, "a public reveal date shows the round");
log = E.listLog(0, 10);
const lb = log.find((x) => x.uid === b.uid);
ok(lb.tl?.round === b.round && lb.tl.ct === b.ct && checkLog().ok, "public date: the ciphertext is in the log and the chain still verifies");
ok(entryProblem({ ...lb, tl: { round: b.round, ct: b.ct.replace(/A/, "B") } }) !== null, "a swapped ciphertext is caught (it is not what the chain covers)");
ok(entryProblem({ ...lb, tl: { round: b.round + 1, ct: b.ct } }) !== null, "a wrong round is caught");
ok(entryProblem({ ...lb, tlHash: null }) !== null && entryHash(lb.prevHash, { ...lb, tlHash: "0".repeat(64) }) !== lb.entryHash, "dropping or changing the hash breaks the chain");
ok(entryProblem({ ...log[0], hashV: 3 }) !== null, "a v3 row cannot carry a time-lock");
{
  // A very long lock stays out of the public log (mirrors page through it) but its hash is still chained.
  const big = await sealLocked({ handle: "Big Bertha", revealPublic: true });
  await big.seal();
  db.prepare("UPDATE entries SET tl_ct = ? WHERE uid = ?").run("x".repeat(20_000), big.uid);
  const lr = E.listLog(0, 1000).find((x) => x.uid === big.uid);
  ok(lr.tlHash === sha(big.ct) && lr.tl === null && entryProblem(lr) === null, "a very long lock is not published in the log, only its hash, and the row still verifies");
  db.prepare("UPDATE entries SET tl_ct = ? WHERE uid = ?").run(big.ct, big.uid);
  ok(E.listLog(0, 1000).find((x) => x.uid === big.uid).tl?.ct === big.ct, "an ordinary lock is published");
}

// the older path still works, in the same chain
{
  const uid = crypto.randomUUID(), nonce = CC.randomHex(16), text = `A legacy style entry for the old pages ${uid}`;
  const content = { uid, title: "Legacy", text, placeMode: "none", place: null, secretCommit: null, mode: "date" };
  const res = await E.sealEntry({ uid, title: "Legacy", text, placeMode: "none", commitV: 2, commitment: await CC.commitmentV2(key, nonce, content), nonce, mode: "date",
    revealAt: Date.now() + 120_000, opening: await CC.makeOpeningV2(key, uid, nonce, "Old Olga") });
  ok(res.hashVersion === 3 && res.timelock === null && checkLog().ok && E.verifyChain().ok, "an entry from an older page is still accepted (v3), in the same chain");
}

// ===================================================================== refusals
const mk = () => sealLocked({ handle: "Refused" });
await rejects((async () => { const x = await mk(); return E.sealEntry({ ...x.input, mode: "manual", revealAt: null }); })(), /Only dated and locked/, "a manual entry cannot be time-locked");
await rejects((async () => { const x = await mk(); return E.sealEntry({ ...x.input, opening: x.opening }); })(), /must not also send/, "the opening may not travel alongside the lock");
await rejects((async () => { const x = await sealLocked({ handle: "Refused", hiddenPlace: true }); return E.sealEntry({ ...x.input, secret: x.secret }); })(), /must not also send/, "nor the hidden parts");
await rejects((async () => { const x = await mk(); return E.sealEntry({ ...x.input, secret: { parts: [], place: null, salt: "x" } }); })(), /hidden words/, "and hidden parts for an entry that has none are refused as before");
await rejects((async () => { const x = await sealLocked({ handle: "Wrong round", lockRound: TL.roundForTime(Date.now() + 9_000_000) }); return x.seal(); })(), /doesn.t match the reveal date/, "a lock to a different round than the reveal date is refused");
await rejects((async () => { const x = await mk(); return E.sealEntry({ ...x.input, timelock: { round: x.round + 1, ct: x.ct } }); })(), /time-lock is not valid/, "a round that differs from the ciphertext's is refused");
await rejects((async () => { const x = await mk(); return E.sealEntry({ ...x.input, timelock: { round: x.round, ct: "not a ciphertext" } }); })(), /time-lock is not valid/, "garbage is refused");
await rejects((async () => { const x = await mk(); return E.sealEntry({ ...x.input, timelock: { round: x.round, ct: x.ct.replace("\n", "\r\n") } }); })(), /time-lock is not valid/, "a malformed armor is refused");
await rejects((async () => { const x = await mk(); return E.sealEntry({ ...x.input, timelock: { round: x.round, ct: "A".repeat(70_000) } }); })(), /time-lock is not valid/, "an oversize ciphertext is refused");
await rejects((async () => { const x = await mk(); return E.sealEntry({ ...x.input, timelock: null }); })(), /Add a name/, "without a lock or an opening a dated entry still needs a name");
ok(db.prepare("SELECT COUNT(*) AS n FROM entries").get().n === 4, "no refused entry was recorded");

// ===================================================================== release
// Entries whose rounds are in the past: swap in a ciphertext made for a real past round.
function makeDue(x, { round = 1000000, ct, bundle } = {}) {
  const c = ct ?? TL.timelockEncrypt(RB.encodeBundle(bundle ?? { opening: x.opening, secret: x.secret }), round);
  db.prepare("UPDATE entries SET tl_ct = ?, tl_round = ?, tl_hash = ?, reveal_at = ? WHERE uid = ?").run(c, round, sha(c), TL.timeOfRound(round) + 1, x.uid);
}
const calls = [];
const realFetch = globalThis.fetch;
const relays = { "api.drand.sh": "lies", "api2.drand.sh": "truth", "api3.drand.sh": "truth", "drand.cloudflare.com": "truth" };
globalThis.fetch = async (url) => {
  const u = new URL(String(url));
  calls.push(u.host);
  const m = /\/public\/(\d+)$/.exec(u.pathname);
  const mode = relays[u.host];
  if (mode === "down") return new Response("down", { status: 503 });
  if (!m || !SIG[m[1]] || u.pathname.split("/")[1] !== TL.QUICKNET.chainHash) return new Response("nope", { status: 404 });
  return Response.json({ round: Number(m[1]), randomness: "00", signature: mode === "lies" ? flipHex(SIG[m[1]]) : SIG[m[1]] });
};

// 1. a lying relay is ignored, the next one answers, and the entry opens itself
makeDue(a);
const waiting = await E.releaseDueTimelocks();
const opened = E.getEntry(a.uid);
ok(waiting === 0 && opened.status === "revealed" && opened.handle === HANDLE, "when the round is published the entry reveals the author's name");
ok(opened.opening?.handle === HANDLE && opened.secret?.place?.label === "Hidden place" && opened.secret.salt === a.secret.salt, "and its hidden place, matching the commitment");
ok(calls[0] === "api.drand.sh" && calls.includes("api2.drand.sh"), "the lying relay was asked first and its answer was thrown away");
ok(db.prepare("SELECT sig FROM beacons WHERE round = 1000000").get()?.sig === SIG[1000000], "only the verified signature was kept");
const callsAfterFirst = calls.length;

// 2. the signature is cached: a second entry for the same round needs no network
const c = await sealLocked({ handle: "Cached Cleo" });
await c.seal();
makeDue(c);
ok((await E.releaseDueTimelocks()) === 0 && st(c.uid).handle === "Cached Cleo" && calls.length === callsAfterFirst, "a second entry for the same round opens without another fetch");

// 3. beacon unreachable: nothing happens, nothing is lost, and it opens when the relays return
const d = await sealLocked({ handle: "Delayed Dara" });
await d.seal();
makeDue(d, { round: 2000000 });
for (const h of Object.keys(relays)) relays[h] = "down";
ok((await E.releaseDueTimelocks()) === 1 && st(d.uid).revealed_at === null, "with no beacon the entry waits");
ok(st(d.uid).tl_error === null, "and is not marked as failed");
relays["api.drand.sh"] = "truth";
ok((await E.releaseDueTimelocks()) === 0 && st(d.uid).handle === "Delayed Dara", "it opens once a relay answers");

// 4. a lock that holds something else is marked failed and never reveals
const e1 = await sealLocked({ handle: "Imposter" });
await e1.seal();
const otherOpening = await CC.makeOpeningV2(key, crypto.randomUUID(), e1.nonce, "Imposter"); // proof made for another entry id
makeDue(e1, { bundle: { opening: otherOpening, secret: null } });
await E.releaseDueTimelocks();
ok(st(e1.uid).revealed_at === null && st(e1.uid).tl_error, "an opening that does not match the entry is refused and the entry marked");
const callsBefore = calls.length;
await E.releaseDueTimelocks();
ok(calls.length === callsBefore, "a failed entry is not retried");

const e2 = await sealLocked({ handle: "Wrong secret", hiddenPlace: true });
await e2.seal();
makeDue(e2, { bundle: { opening: e2.opening, secret: CC.makeSecret([], { lat: 1, lng: 2, label: "A different place" }) } });
await E.releaseDueTimelocks();
ok(st(e2.uid).revealed_at === null && st(e2.uid).tl_error, "hidden parts that do not match their commitment are refused");

const e3 = await sealLocked({ handle: "Garbage" });
await e3.seal();
makeDue(e3, { ct: TL.timelockEncrypt(new TextEncoder().encode("this is not a bundle"), 1000000) });
await E.releaseDueTimelocks();
ok(st(e3.uid).revealed_at === null && st(e3.uid).tl_error, "a lock holding no bundle is refused");

const e4 = await sealLocked({ handle: "Wrong round" });
await e4.seal();
makeDue(e4, { ct: TL.timelockEncrypt(RB.encodeBundle({ opening: e4.opening, secret: null }), 2000000), round: 1000000 }); // says 1000000, was locked to 2000000
await E.releaseDueTimelocks();
ok(st(e4.uid).revealed_at === null && st(e4.uid).tl_error, "a lock that does not open with its round's beacon is refused");

// 5. a round that has not been published cannot be opened, whatever reveal_at says
const f = await sealLocked({ handle: "Not yet" });
await f.seal();
db.prepare("UPDATE entries SET reveal_at = ? WHERE uid = ?").run(Date.now() - 1000, f.uid); // reveal_at says due; the round says no
const callsBeforeF = calls.length;
await E.releaseDueTimelocks();
ok(st(f.uid).revealed_at === null && calls.length === callsBeforeF, "a round still in the future is neither fetched nor opened");
ok((await B.getBeacon(TL.roundForTime(Date.now() + 3_600_000))) === null && (await B.getBeacon(0)) === null && (await B.getBeacon(1.5)) === null, "no beacon for a future or invalid round");

// 6. the author can still reveal early (a dated entry only); a locked one cannot
const g = await sealLocked({ handle: "Early Edna", hiddenPlace: true });
await g.seal();
const early = await E.revealEntry(g.uid, { ...g.opening, secret: g.secret });
ok(early.status === "revealed" && early.handle === "Early Edna" && early.secret?.place?.label === "Hidden place", "an author can still reveal a dated, time-locked entry early with their key");
makeDue(g);
await E.releaseDueTimelocks();
ok(st(g.uid).revealed_at === early.revealedAt, "and the release pass leaves it alone afterwards");
const h = await sealLocked({ handle: "Locked Lou", mode: "locked" });
await h.seal();
await rejects(E.revealEntry(h.uid, { ...h.opening }), /locked/, "a locked entry cannot be revealed early");

// 7. a stranger with only a mirror's copy of the log can open it, with no help from the server
globalThis.fetch = realFetch;
{
  const { spawn } = await import("node:child_process");
  const http = await import("node:http");
  makeDue(b); // the public-date entry from earlier, now with a lock to a real past round
  const later = await sealLocked({ handle: "Later Lena", revealPublic: true });
  await later.seal(); // a public lock whose round has not come
  const mirror = path.join(tmp, "mirror");
  fs.mkdirSync(mirror);
  fs.writeFileSync(path.join(mirror, "entries.jsonl"), E.listLog(0, 1000).map((x) => JSON.stringify(x) + "\n").join(""));
  let relayMode = "lies";
  const srv = http.createServer((req, res) => {
    const m = /^\/([0-9a-f]{64})\/public\/(\d+)$/.exec(req.url);
    if (!m || m[1] !== TL.QUICKNET.chainHash || !SIG[m[2]]) { res.statusCode = 404; return res.end("no"); }
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ round: Number(m[2]), randomness: "00", signature: relayMode === "lies" ? flipHex(SIG[m[2]]) : SIG[m[2]] }));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const open = () => new Promise((resolve) => {
    const child = spawn(process.execPath, ["--no-warnings", "--experimental-transform-types", "--import", path.join(root, "scripts/ts-resolve.mjs"), path.join(root, "scripts/timelock-open.mjs"),
      "--log", mirror, "--relay", `http://127.0.0.1:${srv.address().port}`, "--json"], { cwd: root });
    let out = "", err = "";
    child.stdout.on("data", (d) => (out += d)); child.stderr.on("data", (d) => (err += d));
    child.on("close", (code) => resolve({ code, out, err }));
  });
  let r = await open();
  let rows = JSON.parse(r.out || "[]");
  ok(r.code === 0 && rows.length >= 3, "the opener reads every time-lock that has a public ciphertext (public dates, and entries already revealed)\n" + r.out + r.err);
  ok(rows.every((x) => x.state === "no-beacon" || x.state === "locked") && rows.find((x) => x.uid === b.uid).state === "no-beacon", "a lying relay gets nothing opened");
  relayMode = "truth";
  r = await open();
  rows = JSON.parse(r.out);
  const rb = rows.find((x) => x.uid === b.uid), rl = rows.find((x) => x.uid === later.uid);
  ok(rb.state === "opened" && rb.handle === "Public Priya", "with an honest beacon it opens the entry from the mirror's copy alone, and verifies it against the commitment");
  ok(rl.state === "locked" && rl.opensInSeconds > 0, "an entry whose round has not come stays locked");
  // Everything this server revealed is something a stranger opens to the very same name.
  const revealed = db.prepare("SELECT uid, handle FROM entries WHERE revealed_at IS NOT NULL AND tl_ct IS NOT NULL").all();
  ok(revealed.length >= 4 && revealed.every((v) => rows.find((x) => x.uid === v.uid)?.state === "opened" && rows.find((x) => x.uid === v.uid).handle === v.handle), "every reveal the server made, a stranger opens to the same name");
  srv.close();
}

console.log(`${n} checks passed`);
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(0);

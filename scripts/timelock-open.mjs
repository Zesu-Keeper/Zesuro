#!/usr/bin/env node
// Opens time-locked reveals WITHOUT the server: from a mirror's copy of the log, a drand beacon, and
// nothing else. This is the point of the time-lock: once a round has been published, anyone can do
// this, so a server that is down, slow, or unwilling cannot keep a reveal back.
//
//   node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs \
//        scripts/timelock-open.mjs --log <mirror folder> [--relay https://api.drand.sh] [--json]
//
// For every entry in <folder>/entries.jsonl that carries a time-lock whose round has been published:
//   1. fetches that round's beacon and checks it against the pinned quicknet public key,
//   2. decrypts the lock, and
//   3. checks the opening inside against the entry's own commitment (the same check a reveal gets).
// Nothing is written anywhere. It does not re-check the hash chain: that is what the mirror does
// (scripts/mirror.mjs) and scripts/verify-log.mjs; here each row is only checked on its own.
// Entries whose reveal date is private have no ciphertext in the log until they are revealed, so a
// mirror cannot open those early; that is the price of keeping the date private.
import fs from "node:fs";
import path from "node:path";
import { entryProblem } from "./log-core.mjs";
import { QUICKNET, timeOfRound, timelockDecrypt, verifyBeacon } from "../src/lib/timelock.ts";
import { decodeBundle } from "../src/lib/release-bundle.ts";
import { parseOpening, verifyOpening } from "../src/lib/opening.ts";
import { countRedactions, parseSecret, secretCommitOf } from "../src/lib/secret.ts";

const argv = process.argv.slice(2);
const opt = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : d; };
const dir = opt("log"), relay = (opt("relay", "https://api.drand.sh") ?? "").replace(/\/+$/, ""), json = argv.includes("--json");
if (!dir || !/^https?:\/\//.test(relay)) { console.error("Use: timelock-open.mjs --log <mirror folder> [--relay https://api.drand.sh] [--json]"); process.exit(64); }
const file = path.join(dir, "entries.jsonl");
if (!fs.existsSync(file)) { console.error(`No ${file}`); process.exit(64); }

const beacons = new Map();
async function beacon(round) {
  if (beacons.has(round)) return beacons.get(round);
  let sig = null;
  try {
    const r = await fetch(`${relay}/${QUICKNET.chainHash}/public/${round}`, { signal: AbortSignal.timeout(8000) });
    const j = r.ok ? await r.json() : null;
    if (j && j.round === round && typeof j.signature === "string" && verifyBeacon(round, j.signature)) sig = j.signature; // a relay is never trusted
  } catch { /* unreachable */ }
  beacons.set(round, sig);
  return sig;
}

const results = [];
for (const line of fs.readFileSync(file, "utf8").split("\n").filter(Boolean)) {
  const x = JSON.parse(line);
  if (x.hashV !== 4 || !x.tl) continue;
  const base = { seq: x.seq, uid: x.uid, title: x.title, round: x.tl.round };
  const bad = entryProblem(x);
  if (bad) { results.push({ ...base, state: "bad-row", why: bad }); continue; }
  const wait = timeOfRound(x.tl.round) - Date.now();
  if (wait > 0) { results.push({ ...base, state: "locked", opensInSeconds: Math.ceil(wait / 1000) }); continue; }
  const sig = await beacon(x.tl.round);
  if (!sig) { results.push({ ...base, state: "no-beacon" }); continue; }
  try {
    const bundle = decodeBundle(timelockDecrypt(x.tl.ct, sig));
    const opening = parseOpening(bundle.opening);
    if (!opening) throw new Error("the lock holds no valid opening");
    const content = { uid: x.uid, title: x.title, text: x.text, placeMode: x.placeMode, place: x.placeMode === "public" ? x.place : null, secretCommit: x.secretCommit, mode: x.mode };
    if (!(await verifyOpening(x.uid, x.commitment, opening, Number(x.commitV ?? 1), content))) throw new Error("the opening does not match the entry's commitment");
    let hidden = null;
    if (x.secretCommit) {
      const s = parseSecret(bundle.secret, countRedactions(x.text), x.placeMode === "hidden");
      if (!s || secretCommitOf(s) !== x.secretCommit) throw new Error("the hidden parts do not match their commitment");
      hidden = s;
    }
    results.push({ ...base, state: "opened", handle: opening.handle, hidden });
  } catch (e) {
    results.push({ ...base, state: "failed", why: e instanceof Error ? e.message : String(e) });
  }
}

if (json) console.log(JSON.stringify(results, null, 2));
else if (!results.length) console.log("No time-locked entries with a public ciphertext in this log.");
else for (const r of results) {
  const head = `#${r.seq} "${r.title}" (round ${r.round})`;
  if (r.state === "opened") console.log(`${head}: OPENED. Written by "${r.handle}", verified against the entry's commitment.${r.hidden ? " Hidden parts match their commitment too." : ""}`);
  else if (r.state === "locked") console.log(`${head}: still locked, opens in about ${r.opensInSeconds}s.`);
  else if (r.state === "no-beacon") console.log(`${head}: the round is published but ${relay} did not give a valid beacon. Try another relay.`);
  else console.log(`${head}: ${r.state.toUpperCase()}: ${r.why}`);
}
process.exit(results.some((r) => r.state === "failed" || r.state === "bad-row") ? 2 : 0);

#!/usr/bin/env node
// Checks a Zesuro site's record without trusting its own "verified" badge. Needs only Node 22.
//   node scripts/verify-log.mjs https://zesuro.com [--root <root public key, zs1.…>]
// It downloads every entry and comment, recomputes both hash chains from scratch, and then
// checks each signed anchor: that its signature is the site's, and that the tips it signed are
// the tips of the chains you just recomputed at that point. It then checks every witness
// signature on each anchor: a witness is a mirror run by someone else that held this same record
// at the time it signed.
// With --root (the root key you got from the operator, not from the site) it also checks that
// each anchor was signed by the server the root key delegated that part of the record to. Without
// it, the site's own published key is taken on trust, which proves only that the site agrees with itself.
// Independent of the site's code: scripts/log-core.mjs holds the whole definition of the chains.
import { createPublicKey, verify } from "node:crypto";
import { ZERO, anchorSigner, authorityProblem, commentHash, commentProblem, currentWriter, entryHash, entryProblem, sha } from "./log-core.mjs";
import { isHybridKey } from "./hybrid-sig.mjs";

const base = (process.argv[2] || "").replace(/\/+$/, "");
const ri = process.argv.indexOf("--root"), root = ri >= 0 ? process.argv[ri + 1] : "";
if (!/^https?:\/\//.test(base) || (ri >= 0 && !isHybridKey(root))) { console.error("Usage: node scripts/verify-log.mjs https://zesuro.com [--root <root public key starting zs1.>]"); process.exit(2); }
const get = async (p) => { const r = await fetch(base + p); if (!r.ok) throw new Error(`${p}: ${r.status}`); return r.json(); };
let bad = 0;
const fail = (m) => { bad++; console.log("FAIL  " + m); };

// Entries (hash version 3). Older formats are not covered by this script.
const entryTips = [ZERO]; // entryTips[n] = tip after n entries
for (let after = 0; ;) {
  const { entries } = await get(`/api/log?after=${after}&limit=1000`);
  if (!entries.length) break;
  for (const x of entries) {
    const prev = entryTips[entryTips.length - 1];
    const bad = entryProblem(x);
    if (bad) { fail(`entry ${x.seq}: ${bad}`); process.exit(1); }
    if (x.prevHash !== prev) fail(`entry ${x.seq}: does not follow the entry before it`);
    if (entryHash(prev, x) !== x.entryHash) fail(`entry ${x.seq}: its hash is not what its contents give`);
    if (x.seq !== entryTips.length) fail(`entry ${x.seq}: numbering has a gap`);
    entryTips.push(x.entryHash);
    after = x.seq;
  }
}
const commentTips = [ZERO];
for (let after = 0; ;) {
  const { comments } = await get(`/api/log/comments?after=${after}&limit=1000`);
  if (!comments.length) break;
  for (const x of comments) {
    const prev = commentTips[commentTips.length - 1];
    const bad = commentProblem(x);
    if (bad) { fail(`comment ${x.id}: ${bad}`); process.exit(1); }
    if (x.prevHash !== prev) fail(`comment ${x.id}: does not follow the comment before it`);
    if (commentHash(prev, x) !== x.commentHash) fail(`comment ${x.id}: its hash is not what its contents give`);
    commentTips.push(x.commentHash);
    after = x.id;
  }
}
console.log(`${entryTips.length - 1} entries and ${commentTips.length - 1} comments recomputed.`);

// Anchors
const { publicKey, anchors } = await get("/api/anchors?limit=200");
if (!anchors.length) console.log("This site has not published any signed anchors yet, so nothing outside it vouches for this record.");
else {
  let auth = null;
  if (root) {
    try { auth = await get("/api/authority"); } catch { /* handled below */ }
    const problem = auth ? authorityProblem(auth, root) : "the site publishes no authority file";
    if (problem) { fail(`authority: ${problem}`); auth = null; }
    else if (currentWriter(auth) !== publicKey) fail(`authority: the site signs with ${publicKey}, but the root key's latest delegation names ${currentWriter(auth)}`);
  }
  let ok = 0, witnessed = 0;
  const witnesses = new Map(); // key -> name, as the site labels it
  for (const a of anchors) {
    const text = await (await fetch(`${base}/api/anchors/${a.id}/head`)).text();
    const sigOk = !!anchorSigner({ auth, siteKey: root ? null : publicKey }, text, a.sig);
    const h = JSON.parse(text);
    const tipsOk = entryTips[h.entries.count] === h.entries.tip && commentTips[h.comments.count] === h.comments.tip;
    if (!sigOk) fail(root ? `anchor ${a.id}: not signed by the server the root key delegated to` : `anchor ${a.id}: not signed by the site's key`);
    else if (!tipsOk) fail(`anchor ${a.id}: signed tips do not match the record (history was changed after it was anchored)`);
    else ok++;
    let good = 0;
    for (const w of a.witnesses ?? []) {
      let wOk = false;
      try { wOk = verify(null, Buffer.from(`zesuro:witness:v1:${sha(text)}:${w.at}`), createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: w.key }, format: "jwk" }), Buffer.from(w.sig, "base64url")); } catch { /* malformed */ }
      if (!wOk) fail(`anchor ${a.id}: the signature shown for witness "${w.name}" does not verify`);
      else { good++; witnesses.set(w.key, w.name); }
    }
    if (good) witnessed++;
  }
  console.log(`${ok} of ${anchors.length} signed anchors match the record. Site key: ${publicKey}`);
  console.log(root
    ? (auth ? `Signers checked against the root key (${auth.delegations.length} delegation(s)).` : "Signers could NOT be checked against the root key.")
    : "No --root given: the site's own key was trusted, so a replaced or seized server would pass this check. Get the root key from the operator and run again with --root.");
  console.log(witnessed
    ? `${witnessed} of them carry valid signatures from ${witnesses.size} witness(es): ${[...witnesses].map(([k, n]) => `${n} (${k})`).join(", ")}`
    : "None of them is witnessed by anyone else yet, so the times in this record are only this site's word.");
}
console.log(bad ? `\n${bad} problem(s) found` : "\nThe record is consistent.");
process.exit(bad ? 1 : 0);

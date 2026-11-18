// The definition of Zesuro's two hash chains, and the checks for what a server sends.
// Used by scripts/verify-log.mjs and scripts/mirror.mjs. Deliberately has no imports from the
// app: these few formulas are the whole definition, so anyone can read and re-implement them.
import { createHash, createPublicKey as _pub, verify as _verify } from "node:crypto";
import { isHybridKey, verify as hybridVerify } from "./hybrid-sig.mjs";

export const ZERO = "0".repeat(64);
export const sha = (s) => createHash("sha256").update(s).digest("hex");
const HEX64 = /^[0-9a-f]{64}$/;
const int = (n) => Number.isSafeInteger(n) && n >= 0;
const str = (s, max) => typeof s === "string" && s.length <= max;

/**
 * Hash of an entry that follows the entry whose hash is `prev`. Version 4 is version 3 plus the
 * SHA-256 of the entry's time-lock ciphertext (null when it has none), so the ciphertext, once
 * sealed, can't be swapped for another.
 */
export function entryHash(prev, x) {
  const body = [x.hashV === 4 ? 4 : 3, x.seq, x.uid, x.createdAt, x.title, x.text, x.commitment, x.nonce, x.mode, x.schedCommit,
    x.placeMode === "public" ? [x.place.lat, x.place.lng, x.place.label] : null, x.placeMode === "hidden", x.secretCommit];
  if (x.hashV === 4) body.push(x.tlHash);
  return sha(prev + "\n" + JSON.stringify(body));
}

/** Hash of a comment that follows the comment whose hash is `prev`. */
export function commentHash(prev, x) {
  return sha(JSON.stringify(["c2", prev, x.id, x.uid, x.entryUid, x.createdAt, x.textHash, x.tag]));
}

/** Null if `x` has the shape of a log entry, otherwise what is wrong. A server may send anything. */
export function entryProblem(x) {
  if (!x || typeof x !== "object") return "not an object";
  if (!int(x.seq) || x.seq < 1) return "bad number";
  if (x.hashV !== 3 && x.hashV !== 4) return `hash version ${x.hashV} is not covered`;
  if (x.hashV === 3 && (x.tlHash !== undefined || x.tl !== undefined)) return "a version 3 entry has no time-lock";
  if (x.hashV === 4) {
    if (!HEX64.test(x.tlHash ?? "")) return "bad time-lock hash";
    // The ciphertext is optional (a private reveal date keeps it off the public log until the entry is revealed),
    // but if it is there it must be exactly what the chain covers.
    if (x.tl !== null && x.tl !== undefined) {
      if (typeof x.tl !== "object" || !int(x.tl.round) || x.tl.round < 1 || !str(x.tl.ct, 60_000)) return "bad time-lock";
      if (sha(x.tl.ct) !== x.tlHash) return "the time-lock ciphertext is not the one the chain covers";
      const m = /^-> tlock (\d{1,16}) [0-9a-f]{64}$/m.exec(Buffer.from(x.tl.ct.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "").slice(0, 400), "base64").toString("latin1"));
      if (!m || Number(m[1]) !== x.tl.round) return "the time-lock's round is not the one in its ciphertext";
    }
  }
  if (!str(x.uid, 64) || !str(x.title, 2000) || !str(x.text, 100_000) || !str(x.nonce, 64)) return "bad text field";
  if (!int(x.createdAt)) return "bad time";
  if (!["manual", "date", "locked"].includes(x.mode)) return "bad mode";
  if (!HEX64.test(x.commitment ?? "") || !HEX64.test(x.schedCommit ?? "") || !HEX64.test(x.prevHash ?? "") || !HEX64.test(x.entryHash ?? "")) return "bad hash field";
  if (!["none", "public", "hidden"].includes(x.placeMode)) return "bad place mode";
  if (x.placeMode === "public" && !(x.place && typeof x.place.lat === "number" && typeof x.place.lng === "number" && str(x.place.label, 500))) return "bad place";
  if (x.secretCommit !== null && !HEX64.test(x.secretCommit ?? "")) return "bad secret commitment";
  return null;
}

export function commentProblem(x) {
  if (!x || typeof x !== "object") return "not an object";
  if (!int(x.id) || x.id < 1) return "bad number";
  if (!str(x.uid, 64) || !str(x.entryUid, 64) || !str(x.tag, 200)) return "bad text field";
  if (!int(x.createdAt)) return "bad time";
  if (!HEX64.test(x.textHash ?? "") || !HEX64.test(x.prevHash ?? "") || !HEX64.test(x.commentHash ?? "")) return "bad hash field";
  return null;
}

// ---------------------------------------------------------------- who may write the record
// The record has one writer at a time: the server the root key has delegated to. authority.json
// (served at /api/authority) is { v, root, recovery, delegations: [{ head, sig }] } where each
// head is the JSON text  { v, type: "delegation", serial, writer, from: { entries: { count, tip },
// comments: { count, tip } }, at }  signed by the root key. Serials run 1, 2, 3…; each delegation
// takes over at its `from` point and ends the one before it there.
const KEY43 = /^[A-Za-z0-9_-]{43}$/;
// The root key must be a hybrid (zs1) key, so its delegations need both Ed25519 and SLH-DSA to forge.
// A writer key may be a hybrid key or, for older servers, a bare Ed25519 key (43 characters).
// A recovery key is "zk1.<x25519>.<ml-kem-768>" (hybrid) or, for older setups, a bare X25519 key.
const RECOVERY = /^(?:[A-Za-z0-9_-]{43}|zk1\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{1579})$/;
export const isRecoveryKey = (k) => typeof k === "string" && RECOVERY.test(k);
export const isWriterKey = (k) => typeof k === "string" && (KEY43.test(k) || isHybridKey(k));
/** Verify a writer's signature over an anchor's head text, whichever kind of key the writer has. */
export function writerVerify(key, text, sig) {
  return isHybridKey(key) ? hybridVerify(key, "anchor", text, sig) : edVerify(key, text, sig);
}
export function edVerify(pubX, text, sig) {
  try { return _verify(null, Buffer.isBuffer(text) ? text : Buffer.from(text), _pub({ key: { kty: "OKP", crv: "Ed25519", x: pubX }, format: "jwk" }), Buffer.from(String(sig), "base64url")); }
  catch { return false; }
}

/** Parsed delegations, in order. Call only after authorityProblem() returned null. */
export const delegationsOf = (auth) => auth.delegations.map((d) => JSON.parse(d.head));

/** Null if `auth` is a well-formed chain of delegations signed by `root`, otherwise what is wrong. */
export function authorityProblem(auth, root) {
  if (!auth || typeof auth !== "object" || !Array.isArray(auth.delegations)) return "not an authority file";
  if (!isHybridKey(root) || auth.root !== root) return "it is not from the expected (hybrid) root key";
  if (auth.delegations.length > 1000) return "too many delegations";
  let prev = null;
  for (const [i, d] of auth.delegations.entries()) {
    if (typeof d?.head !== "string" || d.head.length > 8000) return `delegation ${i + 1} is malformed`; // carries a 1.6 KB recovery key and maybe a hybrid writer key
    if (!hybridVerify(root, "delegation", d.head, d.sig)) return `delegation ${i + 1} is not signed by the root key (both signatures are required)`;
    let h;
    try { h = JSON.parse(d.head); } catch { return `delegation ${i + 1} is not JSON`; }
    const f = h?.from;
    if (h.v !== 1 || h.type !== "delegation" || h.serial !== i + 1 || !isWriterKey(h.writer) || !int(h.at)) return `delegation ${i + 1} is malformed`;
    // The recovery key snapshots are encrypted to is part of what the root signs. If it were only a
    // loose field, whoever could edit authority.json could swap in a key of their own.
    if (!isRecoveryKey(h.recovery)) return `delegation ${i + 1} does not carry a valid recovery key`;
    if (!int(f?.entries?.count) || !int(f?.comments?.count) || !HEX64.test(f.entries.tip ?? "") || !HEX64.test(f.comments.tip ?? "")) return `delegation ${i + 1} has a malformed starting point`;
    if (prev && (f.entries.count < prev.from.entries.count || f.comments.count < prev.from.comments.count)) return `delegation ${i + 1} starts before the one it replaces`;
    prev = h;
  }
  const last = prev;
  if (last && auth.recovery !== last.recovery) return "the recovery key listed is not the one the root signed in the latest delegation";
  return null;
}

/** The recovery key in force: the one the root signed into the latest delegation. Call after authorityProblem() returned null. */
export const currentRecovery = (auth) => (auth?.delegations?.length ? JSON.parse(auth.delegations[auth.delegations.length - 1].head).recovery : null);

/**
 * Was this signed tip made by the server entitled to write that part of the record?
 * `delegations` from delegationsOf(); `head` is the anchor's parsed text. Returns the writer's key, or null.
 */
export function rightfulWriter(delegations, head, headText, sig, verifyWith = writerVerify) {
  const ec = head?.entries?.count, cc = head?.comments?.count;
  if (!int(ec) || !int(cc)) return null;
  for (const [i, d] of delegations.entries()) {
    const next = delegations[i + 1];
    const started = d.from.entries.count <= ec && d.from.comments.count <= cc;
    const notEnded = !next || (ec <= next.from.entries.count && cc <= next.from.comments.count);
    if (started && notEnded && verifyWith(d.writer, headText, sig)) return d.writer;
  }
  return null;
}

/** Does `next` continue `held`? Same delegations in the same order, possibly with more after. A held authority may never be rewritten. */
export function authorityExtends(held, next) {
  if (!held) return true;
  if (next.delegations.length < held.delegations.length) return false;
  return held.delegations.every((d, i) => d.head === next.delegations[i].head && d.sig === next.delegations[i].sig);
}

/** The writer key the latest delegation names, or null if there is none. */
export const currentWriter = (auth) => (auth?.delegations?.length ? JSON.parse(auth.delegations[auth.delegations.length - 1].head).writer : null);

/**
 * Who signed this anchor, if they had the right to? With a pinned root (`auth` already checked by
 * authorityProblem): the writer the root delegated that part of the record to. Without one, only
 * the key the site publishes, trusted on first use. Returns the signer's key or null.
 */
export function anchorSigner({ auth, siteKey }, headText, sig) {
  let h;
  try { h = JSON.parse(headText); } catch { return null; }
  if (auth) return rightfulWriter(delegationsOf(auth), h, headText, sig);
  return siteKey && writerVerify(siteKey, headText, sig) ? siteKey : null;
}

/**
 * The exact bytes a bare-Ed25519 writer signs for anything other than an anchor, so that a
 * signature made for one purpose (a snapshot manifest) can never be accepted as another (an anchor).
 * Anchor signatures keep their original form (the head text itself) because they already exist.
 */
export const writerBytes = (purpose, text) => Buffer.concat([Buffer.from(`zesuro:writer:v1:${purpose}\0`), Buffer.from(text)]);

/** Verify a writer's signature for `purpose` (other than "anchor"), whichever kind of key the writer has. */
export function writerVerifyFor(key, purpose, text, sig) {
  if (purpose === "anchor") return writerVerify(key, text, sig);
  return isHybridKey(key) ? hybridVerify(key, purpose, text, sig) : edVerify(key, writerBytes(purpose, text), sig);
}

/**
 * Was this snapshot manifest signed by the server entitled to write the record at the point it
 * describes? Same rule as anchors, with its own signature purpose. Returns the writer's key or null.
 */
export function snapshotSigner({ auth, siteKey }, manifestText, sig) {
  let m;
  try { m = JSON.parse(manifestText); } catch { return null; }
  if (m?.v !== 1 || !int(m.at) || !HEX64.test(m.sha256 ?? "") || !int(m.size)) return null;
  const verifyWith = (k, t, s) => writerVerifyFor(k, "snapshot", t, s);
  if (auth) return rightfulWriter(delegationsOf(auth), m, manifestText, sig, verifyWith);
  return siteKey && verifyWith(siteKey, manifestText, sig) ? siteKey : null;
}

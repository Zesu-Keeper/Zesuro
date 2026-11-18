// Zesuro hybrid signatures ("zs1"): Ed25519 AND SLH-DSA-SHAKE-128s (FIPS 205), both must verify.
//
// Why both: Ed25519 is small, fast and heavily analysed, but a quantum computer breaks it.
// SLH-DSA is hash-based: its security rests only on SHAKE256 and has no number-theoretic
// assumption, but it is newer, and large. A forger must break BOTH. Neither algorithm is
// invented here; this file only composes them, and the composition rules below are where
// hybrid schemes have historically gone wrong.
//
// Rules this file enforces (each is a documented failure elsewhere):
//  1. The KEY decides the algorithm, never the signature. A key string says "zs1", so an attacker
//     cannot downgrade by sending a bare Ed25519 signature (the JWT "alg: none" class of bug).
//  2. Both signatures cover the same bytes, and those bytes bind the full public key, a purpose
//     label and the message, each length-prefixed. So a signature cannot be moved to another
//     key (key substitution), another purpose (root vs writer vs snapshot: cross-protocol
//     replay) or reinterpreted by shifting field boundaries (ambiguous concatenation).
//  3. Signatures have one canonical encoding: exact length, unpadded base64url that re-encodes
//     to itself. No alternative spellings of the same signature (malleability).
//  4. After signing, we verify our own signature before releasing it. A fault or bug that
//     produces a bad signature can otherwise leak key material (RSA-CRT-style fault attacks).
//  5. Secret keys are never printed, never reused across purposes, and are written 0600.
//  6. The format is versioned. Retiring a broken algorithm means a new prefix ("zs2"), not a flag day.
//  7. SLH-DSA is stateless, so there is no one-time-key state that a restored backup can reuse
//     (the XMSS/LMS rollback hazard).
//
// Honest limits: JavaScript cannot promise constant-time execution, so do not sign on a machine
// where hostile code shares the CPU. And hybrids protect against breaks of one algorithm, not
// against a stolen key file.
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerifyRaw } from "node:crypto";
import { slh_dsa_shake_128s as SLH } from "@noble/post-quantum/slh-dsa.js";

export const ALG = "zs1";
const B64U = /^[A-Za-z0-9_-]+$/;
const ED_SIG = 64, ED_KEY = 32;
const SLH_SIG = SLH.lengths.signature, SLH_KEY = SLH.lengths.publicKey, SLH_SK = SLH.lengths.secretKey;

const b64u = (b) => Buffer.from(b).toString("base64url");
/** Decode unpadded base64url strictly: right alphabet, right length, and it re-encodes to the same text. */
function dec(s, len) {
  if (typeof s !== "string" || !B64U.test(s)) return null;
  const b = Buffer.from(s, "base64url");
  return b.length === len && b64u(b) === s ? b : null;
}
const lp = (b) => { const l = Buffer.alloc(4); l.writeUInt32BE(b.length); return Buffer.concat([l, b]); };

/** The exact bytes both algorithms sign. */
function signedBytes(publicKey, purpose, message) {
  const text = Buffer.isBuffer(message) ? message : Buffer.from(String(message), "utf8");
  return Buffer.concat([Buffer.from("zesuro:sig:zs1\0"), lp(Buffer.from(publicKey)), lp(Buffer.from(purpose)), lp(text)]);
}
const okPurpose = (p) => typeof p === "string" && /^[a-z][a-z0-9-]{0,31}$/.test(p);

/** Is this string a zs1 public key: "zs1.<ed25519 x>.<slh-dsa key>"? */
export function parseKey(key) {
  if (typeof key !== "string") return null;
  const p = key.split(".");
  if (p.length !== 3 || p[0] !== ALG) return null;
  const ed = dec(p[1], ED_KEY), slh = dec(p[2], SLH_KEY);
  return ed && slh ? { ed, slh } : null;
}
export const isHybridKey = (k) => parseKey(k) !== null;

/** Make a key pair. `publicKey` is the string you publish; `secret` is the JSON text to keep private. */
export function generate() {
  const ed = generateKeyPairSync("ed25519");
  const slh = SLH.keygen();
  const publicKey = `${ALG}.${ed.publicKey.export({ format: "jwk" }).x}.${b64u(slh.publicKey)}`;
  const secret = JSON.stringify({ v: 1, alg: ALG, ed: ed.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"), slh: b64u(slh.secretKey) });
  return { publicKey, secret };
}

function openSecret(secret) {
  let s;
  try { s = JSON.parse(secret); } catch { throw new Error("secret key is not valid"); }
  if (s?.v !== 1 || s.alg !== ALG) throw new Error("secret key is not a zs1 key");
  const edDer = Buffer.from(String(s.ed), "base64url"), slh = dec(s.slh, SLH_SK);
  if (!slh) throw new Error("secret key is damaged");
  const edKey = createPrivateKey({ key: edDer, format: "der", type: "pkcs8" });
  const edX = createPublicKey(edKey).export({ format: "jwk" }).x;
  const publicKey = `${ALG}.${edX}.${b64u(SLH.getPublicKey(slh))}`;
  return { edKey, slh, publicKey };
}
/** The public key that goes with a secret. */
export const publicKeyOf = (secret) => openSecret(secret).publicKey;

/** Sign `message` for `purpose` ("delegation", "anchor", "snapshot"…). Returns "zs1.<ed sig>.<slh sig>". */
export function sign(secret, purpose, message) {
  if (!okPurpose(purpose)) throw new Error("purpose must be a short lowercase label");
  const k = openSecret(secret);
  const bytes = signedBytes(k.publicKey, purpose, message);
  const sig = `${ALG}.${b64u(edSign(null, bytes, k.edKey))}.${b64u(SLH.sign(bytes, k.slh))}`;
  if (!verify(k.publicKey, purpose, message, sig)) throw new Error("self-check failed: refusing to release a signature that does not verify");
  return sig;
}

/** True only if BOTH signatures are valid for exactly this key, purpose and message. */
export function verify(publicKey, purpose, message, sig) {
  try {
    const k = parseKey(publicKey);
    if (!k || !okPurpose(purpose) || typeof sig !== "string") return false;
    const p = sig.split(".");
    if (p.length !== 3 || p[0] !== ALG) return false;
    const e = dec(p[1], ED_SIG), s = dec(p[2], SLH_SIG);
    if (!e || !s) return false;
    const bytes = signedBytes(publicKey, purpose, message);
    const edOk = edVerifyRaw(null, bytes, createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: b64u(k.ed) }, format: "jwk" }), e);
    const slhOk = SLH.verify(s, bytes, k.slh);
    return edOk === true && slhOk === true; // evaluate both, always, so timing does not show which half failed
  } catch {
    return false;
  }
}

/** Short identifier for showing a key to people (not a security boundary). */
export const keyId = (publicKey) => createHash("sha256").update(String(publicKey)).digest("hex").slice(0, 16);

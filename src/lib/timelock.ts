/**
 * Time-lock encryption against the drand "quicknet" randomness beacon.
 *
 * You encrypt to a FUTURE round number. Nobody (not Zesuro's server, not the author) can decrypt
 * until the League of Entropy's threshold of operators publishes that round's signature; once it is
 * published, anyone can. The server therefore stores only ciphertext and cannot read a reveal early.
 *
 * Written against the published scheme (drand/tlock, "tlock" age stanza), on top of
 * @noble/curves / @noble/hashes / @noble/ciphers, so no other package is trusted with the
 * cryptography. The files it makes are ordinary tlock files: `tle -d` (the Go tool) opens them,
 * so a reveal stays readable even if Zesuro is gone. scripts/timelock.test.mjs checks this against
 * the reference JavaScript implementation and against a real, past beacon.
 *
 * Scheme: Boneh-Franklin identity-based encryption with the Fujisaki-Okamoto transform, where the
 * "identity" is the round number and the "private key" is that round's BLS signature (a G1 point,
 * public key on G2). The 16-byte age file key is what the IBE wraps; the message itself is sealed
 * with ChaCha20-Poly1305 in the age STREAM format.
 *
 * What it does NOT give you:
 *  - Post-quantum safety. BLS12-381 is broken by a large quantum computer.
 *  - Independence from drand: if fewer than the threshold of operators collude, nobody opens early;
 *    if a threshold collude, anyone could. A beacon outage delays a reveal; it cannot release early.
 *  - Revocability: once published, nobody (including the author) can cancel or edit the reveal.
 *
 * Only the pinned quicknet chain is accepted. A ciphertext cannot choose its own chain.
 */
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

export const QUICKNET = {
  chainHash: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  /** BLS public key (G2, compressed). */
  publicKey:
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
  periodSeconds: 3,
  genesisSeconds: 1692803367,
} as const;

/** Largest message accepted (a reveal is short text; this only stops absurd inputs). */
export const MAX_PLAINTEXT = 1 << 20;

const G1_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"; // RFC 9380 suite quicknet uses
const FILE_KEY_LEN = 16;
const VERSION_LINE = "age-encryption.org/v1";
const ARMOR_HEAD = "-----BEGIN AGE ENCRYPTED FILE-----";
const ARMOR_FOOT = "-----END AGE ENCRYPTED FILE-----";
const CHUNK = 64 * 1024;
const TAG = 16;
const enc = new TextEncoder();

// ---------------------------------------------------------------------------------------------
// small helpers

const hexToBytes = (h: string): Uint8Array => {
  if (!/^(?:[0-9a-f]{2})*$/i.test(h)) throw new Error("not hex");
  return Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
};
const bytesToHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const xor = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  if (a.length !== b.length) throw new Error("length mismatch");
  return Uint8Array.from(a, (x, i) => x ^ b[i]);
};
const same = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
};
const randomBytes = (n: number): Uint8Array => globalThis.crypto.getRandomValues(new Uint8Array(n));

function b64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}
/** Unpadded base64 (what age uses in headers). */
const b64u = (b: Uint8Array): string => b64(b).replace(/=+$/, "");
/** Decodes base64 of the given alphabet, refusing anything that would not re-encode to the same text. */
function unb64(s: string, padded: boolean): Uint8Array {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error("bad base64");
  const t = padded ? s : s + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(t);
  const out = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  if ((padded ? b64(out) : b64u(out)) !== s) throw new Error("bad base64");
  return out;
}
const chunked = (s: string, n: number): string[] => s.match(new RegExp(`.{1,${n}}`, "g")) ?? [];

const be64 = (n: number): Uint8Array => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
};

// ---------------------------------------------------------------------------------------------
// the beacon's clock

/** When a round is published: round 1 is at genesis, then one every period. */
export const timeOfRound = (round: number): number => (QUICKNET.genesisSeconds + (round - 1) * QUICKNET.periodSeconds) * 1000;

/** The first round published at or after the given time (ms). */
export function roundForTime(ms: number): number {
  const r = Math.ceil((ms - QUICKNET.genesisSeconds * 1000) / (QUICKNET.periodSeconds * 1000)) + 1;
  return Math.max(1, r);
}

function checkRound(round: number): void {
  if (!Number.isSafeInteger(round) || round < 1) throw new Error("not a valid round number");
}

/** Checks a beacon signature for a round against the pinned public key. Never throws. */
export function verifyBeacon(round: number, signatureHex: string): boolean {
  try {
    checkRound(round);
    const sig = hexToBytes(signatureHex);
    if (sig.length !== 48) return false;
    return bls.shortSignatures.verify(sig, bls.shortSignatures.hash(sha256(be64(round))), hexToBytes(QUICKNET.publicKey));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------
// identity-based encryption (the tlock hashes, byte for byte)

type Fp = bigint;
interface Fp2 { c0: Fp; c1: Fp }
interface Fp6 { c0: Fp2; c1: Fp2; c2: Fp2 }
interface Fp12 { c0: Fp6; c1: Fp6 }

/** 48 bytes, big-endian. */
const fpBytes = (x: Fp): Uint8Array => hexToBytes(x.toString(16).padStart(96, "0"));
const fp2Bytes = (x: Fp2): Uint8Array => concat(fpBytes(x.c1), fpBytes(x.c0));
const fp6Bytes = (x: Fp6): Uint8Array => concat(fp2Bytes(x.c2), fp2Bytes(x.c1), fp2Bytes(x.c0));
const fp12Bytes = (x: Fp12): Uint8Array => concat(fp6Bytes(x.c1), fp6Bytes(x.c0));

const h2 = (gt: Fp12, len: number): Uint8Array => sha256.create().update(enc.encode("IBE-H2")).update(fp12Bytes(gt)).digest().slice(0, len);
const h4 = (sigma: Uint8Array, len: number): Uint8Array => sha256.create().update(enc.encode("IBE-H4")).update(sigma).digest().slice(0, len);

/** Derives the scalar r from (sigma, msg): hash, then retry with a counter until it is below the group order. */
function h3(sigma: Uint8Array, msg: Uint8Array): bigint {
  const base = sha256.create().update(enc.encode("IBE-H3")).update(sigma).update(msg).digest();
  for (let i = 1; i < 65535; i++) {
    const data = sha256.create().update(Uint8Array.of(i & 0xff, i >> 8)).update(base).digest();
    data[0] = data[0] >> 1; // clear the top bit so the value is usually below the 255-bit order
    const n = BigInt("0x" + bytesToHex(data));
    if (n < bls.fields.Fr.ORDER) return n;
  }
  throw new Error("could not derive a scalar");
}

let publicKeyPoint: ReturnType<typeof bls.G2.Point.fromBytes> | null = null;
const pk = () => (publicKeyPoint ??= bls.G2.Point.fromBytes(hexToBytes(QUICKNET.publicKey)));

/** Returns U || V || W for a message of FILE_KEY_LEN bytes. */
function ibeEncrypt(round: number, msg: Uint8Array): Uint8Array {
  const qid = bls.G1.hashToCurve(sha256(be64(round)), { DST: G1_DST });
  const gid = bls.pairing(qid, pk());
  const sigma = randomBytes(msg.length);
  const r = h3(sigma, msg);
  const U = bls.G2.Point.BASE.multiply(r);
  const rGid = bls.fields.Fp12.pow(gid, r) as unknown as Fp12;
  return concat(U.toBytes(true), xor(sigma, h2(rGid, msg.length)), xor(msg, h4(sigma, msg.length)));
}

/** Opens U || V || W with a round's beacon signature. Throws if the signature is not the right one for this ciphertext. */
function ibeDecrypt(signature: Uint8Array, body: Uint8Array): Uint8Array {
  const half = (body.length - 96) / 2;
  if (body.length !== 96 + 2 * FILE_KEY_LEN || half !== FILE_KEY_LEN) throw new Error("not a time-lock ciphertext");
  const Ubytes = body.subarray(0, 96), V = body.subarray(96, 96 + half), W = body.subarray(96 + half);
  const U = bls.G2.Point.fromBytes(Ubytes);
  const key = bls.G1.Point.fromBytes(signature);
  const gid = bls.pairing(key, U) as unknown as Fp12;
  const sigma = xor(V, h2(gid, half));
  const msg = xor(W, h4(sigma, half));
  const r = h3(sigma, msg);
  if (!bls.G2.Point.BASE.multiply(r).equals(U)) throw new Error("that beacon signature does not open this ciphertext");
  return msg;
}

// ---------------------------------------------------------------------------------------------
// age file format (https://age-encryption.org/v1), with one tlock stanza

const macKey = (fileKey: Uint8Array) => hkdf(sha256, fileKey, new Uint8Array(0), enc.encode("header"), 32);
const payloadKey = (fileKey: Uint8Array, nonce: Uint8Array) => hkdf(sha256, fileKey, nonce, enc.encode("payload"), 32);

function streamNonce(counter: number, last: boolean): Uint8Array {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setUint32(7, counter, false); // 11-byte big-endian counter; bytes 0..6 stay zero
  n[11] = last ? 1 : 0;
  return n;
}
function streamSeal(key: Uint8Array, plain: Uint8Array): Uint8Array {
  const chunks = Math.max(1, Math.ceil(plain.length / CHUNK));
  const out: Uint8Array[] = [];
  for (let i = 0; i < chunks; i++)
    out.push(chacha20poly1305(key, streamNonce(i, i === chunks - 1)).encrypt(plain.subarray(i * CHUNK, (i + 1) * CHUNK)));
  return concat(...out);
}
function streamOpen(key: Uint8Array, ct: Uint8Array): Uint8Array {
  if (ct.length < TAG) throw new Error("damaged ciphertext");
  const size = CHUNK + TAG;
  const chunks = Math.ceil(ct.length / size);
  const out: Uint8Array[] = [];
  for (let i = 0; i < chunks; i++) {
    const part = ct.subarray(i * size, (i + 1) * size);
    if (part.length < TAG) throw new Error("damaged ciphertext");
    out.push(chacha20poly1305(key, streamNonce(i, i === chunks - 1)).decrypt(part));
  }
  return concat(...out);
}

/** Encrypts `plain` so that it can be opened once the beacon has published `round`. Returns armored text. */
export function timelockEncrypt(plain: Uint8Array, round: number): string {
  checkRound(round);
  if (plain.length > MAX_PLAINTEXT) throw new Error("message too large");
  const fileKey = randomBytes(FILE_KEY_LEN);
  const stanza = ibeEncrypt(round, fileKey);
  const head = `${VERSION_LINE}\n-> tlock ${round} ${QUICKNET.chainHash}\n${chunked(b64u(stanza), 64).join("\n")}\n---`;
  const mac = b64u(hmac(sha256, macKey(fileKey), enc.encode(head)));
  const nonce = randomBytes(16);
  const file = concat(enc.encode(`${head} ${mac}\n`), nonce, streamSeal(payloadKey(fileKey, nonce), plain));
  const lines = chunked(b64(file), 64);
  const foot = lines.length && lines[lines.length - 1].length === 64 ? "\n" + ARMOR_FOOT : ARMOR_FOOT; // age: a full last line needs an empty one after it
  return `${ARMOR_HEAD}\n${lines.join("\n")}\n${foot}\n`;
}

interface Parsed { round: number; stanza: Uint8Array; head: string; mac: Uint8Array; payload: Uint8Array }

/** Strict reader: exactly one tlock stanza, for the pinned chain, and nothing else. */
function parse(armored: string): Parsed {
  if (typeof armored !== "string" || armored.length > 3 * MAX_PLAINTEXT) throw new Error("not a time-lock file");
  const t = armored.trimStart();
  const s = t.trimEnd();
  if (t.length - s.length > 1024 || !s.startsWith(ARMOR_HEAD) || !s.endsWith(ARMOR_FOOT)) throw new Error("not a time-lock file");
  const body = s.slice(ARMOR_HEAD.length, s.length - ARMOR_FOOT.length);
  // body is "\n" + base64 lines + "\n" (+ one more "\n" if the last line is a full 64, as age requires)
  const rows = body.split("\n");
  if (rows.length < 3 || rows[0] !== "" || rows[rows.length - 1] !== "") throw new Error("not a time-lock file");
  const data = rows.slice(1, -1);
  const fullLast = data[data.length - 1] === "";
  if (fullLast) data.pop();
  const lastLen = data.length ? data[data.length - 1].length : 0;
  if (!data.length || data.slice(0, -1).some((l) => l.length !== 64) || (fullLast ? lastLen !== 64 : lastLen === 0 || lastLen >= 64)) throw new Error("not a time-lock file");
  const file = unb64(data.join(""), true);
  // The header is ASCII up to the first newline after "--- ".
  const text = new TextDecoder("latin1").decode(file.subarray(0, Math.min(file.length, 1024)));
  const end = text.indexOf("\n", text.indexOf("\n--- ") + 1);
  if (text.indexOf("\n--- ") < 0 || end < 0) throw new Error("not a time-lock file");
  const header = text.slice(0, end).split("\n");
  // header: version, "-> tlock R H", base64 lines..., "--- MAC"
  const [version, stanzaLine, ...rest] = header;
  const macLine = rest.pop() ?? "";
  const m = /^-> tlock (\d{1,16}) ([0-9a-f]{64})$/.exec(stanzaLine ?? "");
  if (version !== VERSION_LINE || !m || !macLine.startsWith("--- ")) throw new Error("not a time-lock file");
  if (m[2] !== QUICKNET.chainHash) throw new Error("this file is locked to a different beacon than the one Zesuro trusts");
  const round = Number(m[1]);
  checkRound(round);
  if (rest.length === 0 || rest.slice(0, -1).some((l) => l.length !== 64) || rest[rest.length - 1].length >= 64 || rest[rest.length - 1].length === 0) throw new Error("not a time-lock file");
  return {
    round,
    stanza: unb64(rest.join(""), false),
    head: `${VERSION_LINE}\n-> tlock ${m[1]} ${m[2]}\n${rest.join("\n")}\n---`,
    mac: unb64(macLine.slice(4), false),
    payload: file.subarray(end + 1),
  };
}

/** The round a file is locked to, without decrypting anything. Throws if it is not a valid time-lock file. */
export function lockedRound(armored: string): number {
  return parse(armored).round;
}

/** Opens a file with the beacon signature (hex) for its round. Throws if the signature is wrong or the file damaged. */
export function timelockDecrypt(armored: string, signatureHex: string): Uint8Array {
  const p = parse(armored);
  const sig = hexToBytes(signatureHex);
  if (sig.length !== 48) throw new Error("a beacon signature is 48 bytes");
  const fileKey = ibeDecrypt(sig, p.stanza);
  if (!same(hmac(sha256, macKey(fileKey), enc.encode(p.head)), p.mac)) throw new Error("the file's header does not check out");
  if (p.payload.length < 16 + TAG) throw new Error("damaged ciphertext");
  return streamOpen(payloadKey(fileKey, p.payload.subarray(0, 16)), p.payload.subarray(16));
}

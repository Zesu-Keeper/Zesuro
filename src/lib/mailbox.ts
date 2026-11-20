// Private replies to a post. Runs in the browser and on the server (the server only checks shapes and fingerprints).
//
// When a post is sealed, the author's browser makes twelve mailbox key pairs, one for each month of the next year.
// Each pair is hybrid: X25519 plus ML-KEM-768 (post-quantum). Only the public halves go to the site, and the record
// covers their fingerprint, so nobody, the site included, can later swap them. The private halves stay with the author,
// who throws each month's away when the month is over: a reply sent in a past month can then never be opened, even
// by someone who later gets the author's device.
//
// A reply is locked to the current month's key: a fresh X25519 secret and an ML-KEM secret are mixed with HKDF into an
// AES-256-GCM key. Inside is a short message and a one-time chat link, so the author can answer in a private chat.
// Because only the real author holds the mailbox keys, whoever answers is the author: no proof needed.

import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { gcm } from "@noble/ciphers/aes.js";
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";

export const MONTHS = 12;
export const MONTH_MS = 30 * 86_400_000;
const B64 = /^[A-Za-z0-9_-]+$/;

export interface MailboxLeaf {
  /** X25519 public key, base64url (32 bytes). */
  x: string;
  /** ML-KEM-768 public key, base64url (1184 bytes). */
  k: string;
}
export interface MailboxSecret {
  /** X25519 secret and ML-KEM seed, base64url. Null once the month is over and the key has been thrown away. */
  x: string | null;
  k: string | null;
}

const enc = new TextEncoder();
const dec = new TextDecoder();
export function b64u(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function unb64u(s: string): Uint8Array {
  if (!B64.test(s)) throw new Error("bad encoding");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** The fingerprint the record covers: SHA-256 of the post's id and every month's public keys. */
export function mailboxRootOf(uid: string, leaves: MailboxLeaf[]): string {
  return bytesToHex(sha256(enc.encode(JSON.stringify(["zesuro:mailbox:v1", uid, leaves.map((l) => [l.x, l.k])]))));
}

/** Strict shape check: exactly twelve months of well-formed public keys. */
export function parseMailboxLeaves(raw: unknown): MailboxLeaf[] | null {
  if (!Array.isArray(raw) || raw.length !== MONTHS) return null;
  const out: MailboxLeaf[] = [];
  for (const l of raw) {
    if (!l || typeof l !== "object") return null;
    const { x, k } = l as Record<string, unknown>;
    if (typeof x !== "string" || typeof k !== "string" || !B64.test(x) || !B64.test(k)) return null;
    if (x.length !== 43 || k.length !== 1579) return null;
    out.push({ x, k });
  }
  return out;
}

/** Makes a post's twelve monthly mailbox key pairs. */
export function makeMailbox(): { leaves: MailboxLeaf[]; secrets: MailboxSecret[] } {
  const leaves: MailboxLeaf[] = [];
  const secrets: MailboxSecret[] = [];
  for (let i = 0; i < MONTHS; i++) {
    const xs = randomBytes(32);
    const seed = randomBytes(64);
    leaves.push({ x: b64u(x25519.getPublicKey(xs)), k: b64u(ml_kem768.keygen(seed).publicKey) });
    secrets.push({ x: b64u(xs), k: b64u(seed) });
  }
  return { leaves, secrets };
}

/** Which month's key a reply sent at `now` uses, for a post that went on the record at `sealedAt`. -1 if the year is over. */
export function monthIndex(sealedAt: number, now: number): number {
  const i = Math.floor((now - sealedAt) / MONTH_MS);
  return i >= 0 && i < MONTHS ? i : now < sealedAt ? 0 : -1;
}

/** Throws away the keys of months that are over (with a week's grace for replies still in transit). */
export function expireSecrets(secrets: MailboxSecret[], sealedAt: number, now: number): MailboxSecret[] {
  return secrets.map((s, i) => (sealedAt + (i + 1) * MONTH_MS + 7 * 86_400_000 < now ? { x: null, k: null } : s));
}

const info = (uid: string, idx: number) => enc.encode(`zesuro:mailbox:v1:${uid}:${idx}`);

/** Locks `plain` to month `idx` of a post's mailbox. Format: 01 | idx | ephemeral X25519 (32) | ML-KEM ciphertext (1088) | iv (12) | AES-GCM. */
export function sealReply(uid: string, leaves: MailboxLeaf[], idx: number, plain: string): string {
  const leaf = leaves[idx];
  const eph = randomBytes(32);
  const ephPub = x25519.getPublicKey(eph);
  const ssX = x25519.getSharedSecret(eph, unb64u(leaf.x));
  const kem = ml_kem768.encapsulate(unb64u(leaf.k));
  const ikm = new Uint8Array(64);
  ikm.set(ssX);
  ikm.set(kem.sharedSecret, 32);
  const key = hkdf(sha256, ikm, ephPub, info(uid, idx), 32);
  const iv = randomBytes(12);
  const ct = gcm(key, iv, info(uid, idx)).encrypt(enc.encode(plain));
  const out = new Uint8Array(2 + 32 + kem.cipherText.length + 12 + ct.length);
  out[0] = 1;
  out[1] = idx;
  out.set(ephPub, 2);
  out.set(kem.cipherText, 34);
  out.set(iv, 34 + kem.cipherText.length);
  out.set(ct, 46 + kem.cipherText.length);
  return b64u(out);
}

/** Opens a reply with the author's mailbox secrets. Null if it isn't for this post, its month's key is gone, or it was altered. */
export function openReply(uid: string, secrets: MailboxSecret[], blob: string): { idx: number; plain: string } | null {
  try {
    const raw = unb64u(blob);
    if (raw.length < 2 + 32 + 1088 + 12 + 16 || raw[0] !== 1) return null;
    const idx = raw[1];
    const s = secrets[idx];
    if (!s || !s.x || !s.k) return null;
    const ephPub = raw.slice(2, 34);
    const kemCt = raw.slice(34, 34 + 1088);
    const iv = raw.slice(1122, 1134);
    const ct = raw.slice(1134);
    const ssX = x25519.getSharedSecret(unb64u(s.x), ephPub);
    const ssK = ml_kem768.decapsulate(kemCt, ml_kem768.keygen(unb64u(s.k)).secretKey);
    const ikm = new Uint8Array(64);
    ikm.set(ssX);
    ikm.set(ssK, 32);
    const key = hkdf(sha256, ikm, ephPub, info(uid, idx), 32);
    return { idx, plain: dec.decode(gcm(key, iv, info(uid, idx)).decrypt(ct)) };
  } catch {
    return null;
  }
}

/** What a private reply carries. */
export interface ReplyBody {
  v: 1;
  /** A one-time chat link secret (lib/chat-crypto.ts newInvite): the author answers by opening it. */
  invite: string;
  text: string;
  /** Optional: who the sender says they are, signed with a key their newsroom publishes (lib/journalist.ts). */
  from?: { name: string; domain: string; key: string; sig: string };
}

export function parseReplyBody(plain: string): ReplyBody | null {
  try {
    const o = JSON.parse(plain) as Record<string, unknown>;
    if (o.v !== 1 || typeof o.invite !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(o.invite)) return null;
    if (typeof o.text !== "string" || o.text.length > 4000) return null;
    const f = o.from as Record<string, unknown> | undefined;
    if (f !== undefined) {
      if (!f || typeof f.name !== "string" || typeof f.domain !== "string" || typeof f.key !== "string" || typeof f.sig !== "string") return null;
      if (f.name.length > 80 || f.domain.length > 253 || f.key.length > 64 || f.sig.length > 120) return null;
    }
    return o as unknown as ReplyBody;
  } catch {
    return null;
  }
}

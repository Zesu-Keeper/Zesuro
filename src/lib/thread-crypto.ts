// Private follow-up links ("informant threads"). Browser only.
//
// For each entry, the author's device key derives two per-entry secrets (so the existing key
// backup also covers them, and nothing links one entry's thread to another's):
//   encKey  = HMAC(device key, "whenisaid:thread-enc:v1:"  + nonce)   AES-GCM, 32 bytes
//   seed    = HMAC(device key, "whenisaid:thread-sign:v1:" + nonce)   Ed25519 private key
// The private link is  /e/<uid>#k=<base64url(encKey || Ed25519 public key)>.  The part after
// "#" never leaves the browser, so the server never sees it.
//
// Each comment's 92-byte tag = IV(12) || AES-GCM(encKey, Ed25519 signature(64)).  Ordinary
// comments use 92 random bytes. Link holders decrypt and verify; they can recognise the author
// but can't forge the author, because they don't have the signing key.

import { b64uToBytes, bytesToB64u, type StoredKey } from "./client-crypto";

const enc = new TextEncoder();
const TAG_BYTES = 92;
const PKCS8_ED25519 = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const HELD = "whenisaid.threads.v1";

export interface ThreadKey {
  encKey: Uint8Array<ArrayBuffer>; // 32 bytes
  pub: Uint8Array<ArrayBuffer>; // 32 bytes, Ed25519
}

async function hmac(k: StoredKey, label: string): Promise<Uint8Array<ArrayBuffer>> {
  const hk = await crypto.subtle.importKey(
    "raw",
    b64uToBytes(k.priv.d!),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", hk, enc.encode(label)));
}

/** True if this browser can do Ed25519 (needed to check or post author follow-ups). */
export async function threadsSupported(): Promise<boolean> {
  try {
    await crypto.subtle.importKey(
      "jwk",
      { kty: "OKP", crv: "Ed25519", x: bytesToB64u(new Uint8Array(32)) },
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return true;
  } catch {
    return false;
  }
}

/** The author's own thread key and signing key for one entry. */
export async function authorThread(
  k: StoredKey,
  nonce: string,
): Promise<{ key: ThreadKey; sign: CryptoKey }> {
  const encKey = await hmac(k, `whenisaid:thread-enc:v1:${nonce}`);
  const seed = await hmac(k, `whenisaid:thread-sign:v1:${nonce}`);
  const pkcs8 = new Uint8Array(PKCS8_ED25519.length + 32);
  pkcs8.set(PKCS8_ED25519);
  pkcs8.set(seed, PKCS8_ED25519.length);
  // Extractable only long enough to read the public half; the private key is never stored.
  const tmp = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", tmp);
  const sign = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  return { key: { encKey, pub: b64uToBytes(jwk.x!) }, sign };
}

export function linkFragment(t: ThreadKey): string {
  const b = new Uint8Array(64);
  b.set(t.encKey);
  b.set(t.pub, 32);
  return "k=" + bytesToB64u(b);
}

/** Reads "#k=..." from a private link. Returns null for anything else. */
export function parseFragment(hash: string): ThreadKey | null {
  const m = /^#?k=([A-Za-z0-9_-]{86})$/.exec(hash.trim());
  if (!m) return null;
  try {
    const b = b64uToBytes(m[1]);
    if (b.length !== 64 || bytesToB64u(b) !== m[1]) return null;
    return { encKey: b.slice(0, 32), pub: b.slice(32) };
  } catch {
    return null;
  }
}

function message(entryUid: string, commentUid: string, text: string): Uint8Array<ArrayBuffer> {
  return enc.encode(`whenisaid:comment:v1:${entryUid}:${commentUid}:${text}`);
}

/** Tag for an ordinary comment: indistinguishable random bytes. */
export function randomTag(): string {
  return bytesToB64u(crypto.getRandomValues(new Uint8Array(TAG_BYTES)));
}

/** Tag for the author's follow-up: an encrypted signature over this exact comment. */
export async function authorTag(
  thread: { key: ThreadKey; sign: CryptoKey },
  entryUid: string,
  commentUid: string,
  text: string,
): Promise<string> {
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, thread.sign, message(entryUid, commentUid, text)),
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aes = await crypto.subtle.importKey("raw", thread.key.encKey, { name: "AES-GCM" }, false, [
    "encrypt",
  ]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, sig));
  const out = new Uint8Array(TAG_BYTES);
  out.set(iv);
  out.set(ct, 12);
  return bytesToB64u(out);
}

/** True only if this comment was posted by whoever holds the signing key behind `t`. */
export async function isAuthorComment(
  t: ThreadKey,
  entryUid: string,
  c: { uid: string; text: string; tag: string },
): Promise<boolean> {
  try {
    const raw = b64uToBytes(c.tag);
    if (raw.length !== TAG_BYTES) return false;
    const aes = await crypto.subtle.importKey("raw", t.encKey, { name: "AES-GCM" }, false, [
      "decrypt",
    ]);
    const sig = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: raw.slice(0, 12) },
      aes,
      raw.slice(12),
    );
    const pub = await crypto.subtle.importKey(
      "jwk",
      { kty: "OKP", crv: "Ed25519", x: bytesToB64u(t.pub) },
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify({ name: "Ed25519" }, pub, sig, message(entryUid, c.uid, c.text));
  } catch {
    return false; // random tag, wrong key, or tampered
  }
}

/** Private links this browser has been given, by entry. */
export function loadHeld(entryUid: string): ThreadKey | null {
  try {
    const all = JSON.parse(localStorage.getItem(HELD) || "{}") as Record<string, string>;
    return all[entryUid] ? parseFragment(all[entryUid]) : null;
  } catch {
    return null;
  }
}

export function saveHeld(entryUid: string, t: ThreadKey): void {
  try {
    const all = JSON.parse(localStorage.getItem(HELD) || "{}") as Record<string, string>;
    all[entryUid] = linkFragment(t);
    localStorage.setItem(HELD, JSON.stringify(all));
  } catch {
    /* storage blocked: the key works for this visit only */
  }
}

export function forgetHeld(entryUid: string): void {
  try {
    const all = JSON.parse(localStorage.getItem(HELD) || "{}") as Record<string, string>;
    delete all[entryUid];
    localStorage.setItem(HELD, JSON.stringify(all));
  } catch {
    /* ignore */
  }
}

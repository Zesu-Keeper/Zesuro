// Browser-side crypto. The secret key never leaves the device.
// One ECDSA P-256 key per device; every entry gets its own unlinkable commitment.

const KEY_STORAGE = "whenisaid.key.v1";
const MINE_STORAGE = "whenisaid.mine.v1";
const BACKED_UP = "whenisaid.backedup.v1";
const KEY_PREFIX = "whenisaid-key:v1:";

import { commitInput, contentString, revealMessageV2, type CommitContent } from "./commit";

const enc = new TextEncoder();

export interface StoredKey {
  priv: JsonWebKey; // includes d
  pub: JsonWebKey;
}

export interface Place {
  lat: number;
  lng: number;
  label: string;
}

/** Redacted passages and a hidden place, sealed together. Same shape as the server's Secret. */
export interface Secret {
  parts: string[];
  place: Place | null;
  salt: string;
}

export interface MineEntry {
  uid: string;
  nonce: string;
  title?: string;
  /** The public text, with a REDACTION_MARK wherever something is redacted. */
  text: string;
  createdAt: number;
  mode: "manual" | "date" | "locked";
  /** Kept locally because the public record may hide the reveal date. */
  revealAt?: number | null;
  /** The name sealed with a dated entry; that name is shown whenever it is revealed. */
  handle?: string | null;
  /** Redacted passages and hidden place, kept so the author can release them. */
  secret?: Secret | null;
  /** 2 = per-entry key and content-bound commitment (see lib/commit.ts). Absent = 1. */
  commitV?: 1 | 2;
  /** A delayed post: not on the record yet, and due to appear by this time. */
  pendingBy?: number;
  /** Private replies: the post's monthly mailbox secrets (a month's are thrown away once it is over) and their fingerprint. */
  mailbox?: { root: string; secrets: { x: string | null; k: string | null }[] };
}

/** Marks where a redaction sits in the public text. Must match the server. */
export const REDACTION_MARK = "";

export interface Opening {
  v?: 2;
  pub: { kty: string; crv: string; x: string; y?: string };
  salt: string;
  handle: string;
  sig: string;
}

// ---------- encoding helpers ----------
export function toHex(buf: ArrayBuffer | Uint8Array): string {
  return Array.from(buf instanceof Uint8Array ? buf : new Uint8Array(buf), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

export function bytesToB64u(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uToBytes(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function sha256Hex(s: string): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}

export function randomHex(bytes: number): string {
  return toHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

export function canonicalPub(p: { kty?: string; crv?: string; x?: string; y?: string }): string {
  return JSON.stringify({ crv: p.crv, kty: p.kty, x: p.x, y: p.y });
}

// ---------- key management ----------
export function buildKey(d: string, x: string, y: string): StoredKey {
  return {
    priv: { kty: "EC", crv: "P-256", x, y, d, ext: true, key_ops: ["sign"] },
    pub: { kty: "EC", crv: "P-256", x, y, ext: true, key_ops: ["verify"] },
  };
}

export function loadKey(): StoredKey | null {
  try {
    const raw = localStorage.getItem(KEY_STORAGE);
    return raw ? (JSON.parse(raw) as StoredKey) : null;
  } catch {
    return null;
  }
}

export async function getOrCreateKey(): Promise<StoredKey> {
  const existing = loadKey();
  if (existing) return existing;
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const priv = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const k = buildKey(priv.d!, priv.x!, priv.y!);
  localStorage.setItem(KEY_STORAGE, JSON.stringify(k));
  return k;
}

/** Text form of the key, shown as a QR code for backup. Treat it like a password. */
export function exportKeyString(k: StoredKey): string {
  const payload = JSON.stringify({ d: k.priv.d, x: k.priv.x, y: k.priv.y });
  return KEY_PREFIX + bytesToB64u(enc.encode(payload));
}

export function importKeyString(s: string): StoredKey {
  const t = s.trim();
  if (!t.startsWith(KEY_PREFIX)) throw new Error("That is not a Zesuro key");
  const json = new TextDecoder().decode(b64uToBytes(t.slice(KEY_PREFIX.length)));
  const p = JSON.parse(json) as { d?: string; x?: string; y?: string };
  if (!p.d || !p.x || !p.y) throw new Error("That key is incomplete");
  return buildKey(p.d, p.x, p.y);
}

export function storeKey(k: StoredKey): void {
  localStorage.setItem(KEY_STORAGE, JSON.stringify(k));
}

export function isBackedUp(): boolean {
  try {
    return localStorage.getItem(BACKED_UP) === "1";
  } catch {
    return false;
  }
}
export function markBackedUp(): void {
  try {
    localStorage.setItem(BACKED_UP, "1");
  } catch {
    /* ignore */
  }
}

// ---------- per-entry proofs ----------
/** Salt is secret and unique per entry: HMAC(key = private scalar, msg = public nonce). */
export async function deriveSalt(k: StoredKey, nonce: string): Promise<string> {
  const hk = await crypto.subtle.importKey(
    "raw",
    b64uToBytes(k.priv.d!),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toHex(await crypto.subtle.sign("HMAC", hk, enc.encode(nonce)));
}

export async function commitmentFor(k: StoredKey, nonce: string): Promise<string> {
  return sha256Hex(`${canonicalPub(k.pub)}:${await deriveSalt(k, nonce)}`);
}

export async function makeOpening(
  k: StoredKey,
  uid: string,
  nonce: string,
  handle: string,
): Promise<Opening> {
  const salt = await deriveSalt(k, nonce);
  const sk = await crypto.subtle.importKey(
    "jwk",
    k.priv,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    sk,
    enc.encode(`whenisaid:reveal:v1:${uid}:${handle}`),
  );
  return {
    pub: { kty: "EC", crv: "P-256", x: k.pub.x!, y: k.pub.y! },
    salt,
    handle,
    sig: bytesToB64u(sig),
  };
}

// ---------- version 2: a key per entry, commitment covers the content ----------
const PKCS8_ED25519 = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

async function prf(k: StoredKey, label: string): Promise<Uint8Array<ArrayBuffer>> {
  const hk = await crypto.subtle.importKey(
    "raw",
    b64uToBytes(k.priv.d!),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", hk, enc.encode(label)));
}

/** True if this browser can make the per-entry keys (Ed25519). */
export async function entryKeysSupported(): Promise<boolean> {
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

/**
 * The key for one entry. Derived from the device secret and the entry's public nonce, so it can
 * be re-made after a restore, and two entries never share a public key. The device key's own
 * public half is never published.
 */
export async function entryKey(
  k: StoredKey,
  nonce: string,
): Promise<{ pubX: string; sign: CryptoKey }> {
  const seed = await prf(k, `whenisaid:entry-key:v2:${nonce}`);
  const pkcs8 = new Uint8Array(PKCS8_ED25519.length + 32);
  pkcs8.set(PKCS8_ED25519);
  pkcs8.set(seed, PKCS8_ED25519.length);
  const tmp = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", tmp);
  const sign = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  return { pubX: jwk.x!, sign };
}

export async function deriveSaltV2(k: StoredKey, nonce: string): Promise<string> {
  return toHex(await prf(k, `whenisaid:entry-salt:v2:${nonce}`));
}

export async function commitmentV2(
  k: StoredKey,
  nonce: string,
  content: CommitContent,
): Promise<string> {
  const { pubX } = await entryKey(k, nonce);
  return sha256Hex(commitInput(pubX, await deriveSaltV2(k, nonce), await sha256Hex(contentString(content))));
}

export async function makeOpeningV2(
  k: StoredKey,
  uid: string,
  nonce: string,
  handle: string,
): Promise<Opening> {
  const { pubX, sign } = await entryKey(k, nonce);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, sign, enc.encode(revealMessageV2(uid, handle)));
  return {
    v: 2,
    pub: { kty: "OKP", crv: "Ed25519", x: pubX },
    salt: await deriveSaltV2(k, nonce),
    handle,
    sig: bytesToB64u(sig),
  };
}

/** The opening for an entry this device sealed, whichever version it is. */
export function openingFor(k: StoredKey, m: Pick<MineEntry, "uid" | "nonce" | "commitV">, handle: string) {
  return (m.commitV ?? 1) === 2 ? makeOpeningV2(k, m.uid, m.nonce, handle) : makeOpening(k, m.uid, m.nonce, handle);
}

/** What the public record shows about an entry, as far as its commitment is concerned. */
export interface PublicForCommit {
  uid: string;
  nonce: string;
  commitment: string;
  commitV?: number;
  title: string;
  text: string;
  placeMode: "none" | "public" | "hidden";
  place: { lat: number; lng: number; label: string } | null;
  secretCommit: string | null;
  mode: "manual" | "date" | "locked";
}

/** True only if this device's key made exactly this entry, with exactly this content. */
export async function ownsEntry(k: StoredKey, e: PublicForCommit): Promise<boolean> {
  if ((e.commitV ?? 1) !== 2) return (await commitmentFor(k, e.nonce)) === e.commitment;
  if (!(await entryKeysSupported())) return false;
  return (await commitmentV2(k, e.nonce, e)) === e.commitment;
}

// ---------- redactions and hidden place ----------
/**
 * Splits what the author typed. Anything inside [[double brackets]] is redacted: the public
 * text gets a REDACTION_MARK there and the passage goes into `parts`, in order.
 */
export function splitRedactions(raw: string): { publicText: string; parts: string[] } {
  const parts: string[] = [];
  const clean = raw.split(REDACTION_MARK).join("");
  const publicText = clean.replace(/\[\[([\s\S]*?)\]\]/g, (whole, inner: string) => {
    if (inner.trim() === "") return whole; // an empty [[ ]] stays as typed
    parts.push(inner);
    return REDACTION_MARK;
  });
  return { publicText, parts };
}

const round5 = (n: number) => Math.round(n * 1e5) / 1e5;
/** Places are kept to about 110 m. Finer than that helps nobody and can only identify. */
export const roundPlace = (n: number) => Math.round(n * 1e3) / 1e3;

/** Same cleaning the server applies, so the commitment matches. */
// eslint-disable-next-line no-control-regex
export const cleanLabel = (s: string) => s.replace(/[\u0000-\u001f\u007f]/g, " ").trim().replace(/\s+/g, " ");

export function makeSecret(parts: string[], place: Place | null): Secret {
  return {
    parts,
    place: place ? { lat: roundPlace(place.lat), lng: roundPlace(place.lng), label: cleanLabel(place.label) } : null,
    salt: randomHex(16),
  };
}

/** Must match the server: SHA-256 of JSON.stringify([parts, place, salt]). */
export async function secretCommitOf(s: Secret): Promise<string> {
  return sha256Hex(JSON.stringify([s.parts, s.place, s.salt]));
}

/** The secret is also stored on the server, encrypted with a key only this author can derive. */
async function secretKey(k: StoredKey, nonce: string): Promise<CryptoKey> {
  const hk = await crypto.subtle.importKey(
    "raw",
    b64uToBytes(k.priv.d!),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const raw = await crypto.subtle.sign("HMAC", hk, enc.encode(`whenisaid:secret:v1:${nonce}`));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptSecret(k: StoredKey, nonce: string, s: Secret): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await secretKey(k, nonce),
    enc.encode(JSON.stringify(s)),
  );
  const out = new Uint8Array(iv.length + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), iv.length);
  return bytesToB64u(out);
}

export async function decryptSecret(
  k: StoredKey,
  nonce: string,
  blob: string,
): Promise<Secret | null> {
  try {
    const bytes = b64uToBytes(blob);
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes.slice(0, 12) },
      await secretKey(k, nonce),
      bytes.slice(12),
    );
    return JSON.parse(new TextDecoder().decode(pt)) as Secret;
  } catch {
    return null;
  }
}

// ---------- local list of "my entries" ----------
export function loadMine(): MineEntry[] {
  try {
    const raw = localStorage.getItem(MINE_STORAGE);
    return raw ? (JSON.parse(raw) as MineEntry[]) : [];
  } catch {
    return [];
  }
}

export function addMine(e: MineEntry): void {
  try {
    const list = loadMine().filter((x) => x.uid !== e.uid);
    list.unshift(e);
    localStorage.setItem(MINE_STORAGE, JSON.stringify(list));
  } catch {
    /* storage unavailable: entry is still sealed on the server */
  }
}

/** Replaces one of my entries (for example after its old mailbox keys were thrown away). */
export function updateMine(uid: string, patch: Partial<MineEntry>): void {
  try {
    const list = loadMine().map((x) => (x.uid === uid ? { ...x, ...patch } : x));
    localStorage.setItem(MINE_STORAGE, JSON.stringify(list));
  } catch {
    /* storage unavailable */
  }
}

/** After restoring a key on a new device: find my entries by testing each public commitment. */
export async function findMineIn(
  k: StoredKey,
  entries: (PublicForCommit & { secretBlob?: string | null; createdAt: number })[],
): Promise<MineEntry[]> {
  const found: MineEntry[] = [];
  for (const e of entries) {
    if (await ownsEntry(k, e)) {
      // Recover the redacted parts and hidden place from the encrypted copy on the server.
      const secret = e.secretBlob ? await decryptSecret(k, e.nonce, e.secretBlob) : null;
      found.push({
        uid: e.uid,
        nonce: e.nonce,
        title: e.title,
        text: e.text,
        createdAt: e.createdAt,
        mode: e.mode,
        secret,
        commitV: (e.commitV ?? 1) === 2 ? 2 : 1,
      });
    }
  }
  return found;
}

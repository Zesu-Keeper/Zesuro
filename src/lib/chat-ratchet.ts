// Forward secrecy for private chat: a Double Ratchet (the scheme Signal uses), built from WebCrypto only.
//
// Every message is locked with its own key, and each key is erased as soon as it has been used. The
// two sides also keep swapping fresh Diffie-Hellman keys. Two things follow:
//   - Someone who gets hold of a device or its keys later cannot unlock messages that were already sent
//     and read, even if they saved every scrambled copy from the server.
//   - If a device was briefly compromised, the chat protects itself again after the next reply.
//
// Curve P-256 for the key swaps, HKDF-SHA256 for the root and chain keys, HMAC-SHA256 to step a chain,
// AES-256-GCM for each message. Pure functions: a state goes in and a new state comes out, so a message
// that fails to open can never leave the state half changed.
//
// Wire format of a message (base64url of):  02 | pn (u32) | n (u32) | sender's ratchet key (65 bytes) | iv (12) | ciphertext
// The header is bound to the message as authenticated data. The server sees it; it learns the message
// counts it could already count, and a public key that looks random.

import {
  bytes,
  copy,
  fromB64u,
  hkdf,
  packMessage,
  toB64u,
  unpackMessage,
  type Body,
  type Message,
  type Role,
} from "./chat-crypto";

const enc = new TextEncoder();
type Bytes = Uint8Array<ArrayBuffer>;
const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;
const VERSION = 2;
const HEADER = 1 + 4 + 4 + 65;
/** The most messages one side may be ahead of the other before we refuse (skipped keys are kept for late ones). */
export const MAX_SKIP = 2000;
const MAX_KEPT = 2000;

export interface RatchetState {
  v: 2;
  role: Role;
  /** Root key. */
  rk: string;
  /** Our current ratchet key pair: private half (JWK) and public half (raw, base64url). */
  dhsPriv: JsonWebKey;
  dhsPub: string;
  /** The other side's current ratchet public key. Null until we have heard from them (the side that opened the link). */
  dhr: string | null;
  /** Sending and receiving chain keys. */
  cks: string | null;
  ckr: string | null;
  /** Messages sent / received in the current chains, and how long our previous sending chain was. */
  ns: number;
  nr: number;
  pn: number;
  /** Keys for messages that arrived late or out of order, by "<their ratchet key>:<number>". */
  skipped: Record<string, string>;
  /** Everything this side has sent, so far. It is the running number inside each message. */
  sent: number;
}

const clone = (s: RatchetState): RatchetState => JSON.parse(JSON.stringify(s)) as RatchetState;

// ---------- primitives ----------
async function genPair(): Promise<{ priv: JsonWebKey; pub: string }> {
  const pair = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
  return {
    priv: await crypto.subtle.exportKey("jwk", pair.privateKey),
    pub: toB64u(await crypto.subtle.exportKey("raw", pair.publicKey)),
  };
}

async function dh(priv: JsonWebKey, pub: string): Promise<Bytes> {
  const a = await crypto.subtle.importKey("jwk", priv, ECDH, false, ["deriveBits"]);
  const b = await crypto.subtle.importKey("raw", fromB64u(pub), ECDH, false, []);
  return copy(await crypto.subtle.deriveBits({ name: "ECDH", public: b }, a, 256));
}

/** (root key, DH output) -> (new root key, chain key) */
async function kdfRk(rk: string, dhOut: Bytes): Promise<[string, string]> {
  const out = await hkdf(dhOut, fromB64u(rk), "zesuro:dr:root:v1", 512);
  return [toB64u(out.slice(0, 32)), toB64u(out.slice(32))];
}

async function hmac(key: Bytes, data: number): Promise<Bytes> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return copy(await crypto.subtle.sign("HMAC", k, new Uint8Array([data])));
}

/** (chain key) -> (message key, next chain key). The old chain key is gone once the caller drops it. */
async function kdfCk(ck: string): Promise<[string, string]> {
  const k = fromB64u(ck);
  return [toB64u(await hmac(k, 1)), toB64u(await hmac(k, 2))];
}

async function messageKey(mk: string): Promise<CryptoKey> {
  const raw = await hkdf(fromB64u(mk), bytes(32), "zesuro:dr:message:v1", 256);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

const u32 = (n: number) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const readU32 = (b: Uint8Array, at: number) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;

function aadFor(roomId: string, header: Uint8Array): Bytes {
  const base = enc.encode(`zesuro:chat:v2:msg:${roomId}`);
  const out = bytes(base.length + header.length);
  out.set(base);
  out.set(header, base.length);
  return out;
}

/** The root key both sides start from: only the master the key exchange produced, for this room. */
export async function rootFromMaster(master: string, roomId: string): Promise<string> {
  return toB64u(await hkdf(fromB64u(master), bytes(0), `zesuro:dr:start:v1:${roomId}`, 256));
}

// ---------- starting ----------
/**
 * The person who made the link. They know the opener's public key from the key exchange, so they can
 * send straight away.
 */
export async function startAsCreator(master: string, roomId: string, theirPub: string): Promise<RatchetState> {
  const rk0 = await rootFromMaster(master, roomId);
  const mine = await genPair();
  const [rk, cks] = await kdfRk(rk0, await dh(mine.priv, theirPub));
  return {
    v: 2, role: "a", rk, dhsPriv: mine.priv, dhsPub: mine.pub, dhr: theirPub,
    cks, ckr: null, ns: 0, nr: 0, pn: 0, skipped: {}, sent: 0,
  };
}

/** The person who opened the link. They keep the key pair they made for the exchange and wait for the first message. */
export async function startAsOpener(master: string, roomId: string, priv: JsonWebKey, pub: string): Promise<RatchetState> {
  const rk = await rootFromMaster(master, roomId);
  return {
    v: 2, role: "b", rk, dhsPriv: priv, dhsPub: pub, dhr: null,
    cks: null, ckr: null, ns: 0, nr: 0, pn: 0, skipped: {}, sent: 0,
  };
}

// ---------- sending ----------
export function canSend(s: RatchetState): boolean {
  return s.cks !== null;
}

/** Locks one message. Returns the new state, the blob for the server and the message as it was written. */
export async function ratchetEncrypt(
  state: RatchetState,
  roomId: string,
  body: Body,
): Promise<{ state: RatchetState; blob: string; msg: Message }> {
  if (!state.cks) throw new Error("This chat can't send yet: the other person has to connect first.");
  const s = clone(state);
  const [mk, next] = await kdfCk(s.cks!);
  const header = new Uint8Array(HEADER);
  header[0] = VERSION;
  header.set(u32(s.pn), 1);
  header.set(u32(s.ns), 5);
  header.set(fromB64u(s.dhsPub), 9);
  const iv = crypto.getRandomValues(bytes(12));
  const plain = packMessage(s.role, s.sent, body, 2);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aadFor(roomId, header) }, await messageKey(mk), plain),
  );
  const out = bytes(HEADER + 12 + ct.length);
  out.set(header);
  out.set(iv, HEADER);
  out.set(ct, HEADER + 12);
  const msg = unpackMessage(plain, s.role, 2)!;
  s.cks = next;
  s.ns += 1;
  s.sent += 1;
  return { state: s, blob: toB64u(out), msg };
}

// ---------- receiving ----------
async function skipTo(s: RatchetState, until: number): Promise<void> {
  if (s.ckr === null) return;
  if (until - s.nr > MAX_SKIP) throw new Error("too many skipped");
  while (s.nr < until) {
    const [mk, next] = await kdfCk(s.ckr);
    s.skipped[`${s.dhr}:${s.nr}`] = mk;
    s.ckr = next;
    s.nr += 1;
  }
  const keys = Object.keys(s.skipped);
  for (let i = 0; i < keys.length - MAX_KEPT; i++) delete s.skipped[keys[i]];
}

async function step(s: RatchetState, theirNew: string): Promise<void> {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhr = theirNew;
  [s.rk, s.ckr] = await kdfRk(s.rk, await dh(s.dhsPriv, theirNew));
  const fresh = await genPair();
  s.dhsPriv = fresh.priv;
  s.dhsPub = fresh.pub;
  [s.rk, s.cks] = await kdfRk(s.rk, await dh(fresh.priv, theirNew));
}

/**
 * Opens one blob from the other side. Null if it is not a genuine, well-formed message from them (the
 * state is then untouched); otherwise the new state and the message. A blob this side sent itself cannot
 * be opened: its key is already gone, which is the point.
 */
export async function ratchetDecrypt(
  state: RatchetState,
  roomId: string,
  blob: string,
): Promise<{ state: RatchetState; msg: Message } | null> {
  try {
    const raw = fromB64u(blob);
    if (raw.length < HEADER + 12 + 16 || raw[0] !== VERSION) return null;
    const header = raw.slice(0, HEADER);
    const pn = readU32(header, 1);
    const n = readU32(header, 5);
    const theirs = toB64u(header.slice(9, HEADER));
    if (n > 1_000_000_000 || pn > 1_000_000_000) return null;
    const iv = raw.slice(HEADER, HEADER + 12);
    const ct = raw.slice(HEADER + 12);
    const s = clone(state);
    const from: Role = s.role === "a" ? "b" : "a";

    let mk: string;
    const stored = s.skipped[`${theirs}:${n}`];
    if (stored !== undefined) {
      mk = stored;
      delete s.skipped[`${theirs}:${n}`];
    } else {
      if (theirs !== s.dhr) {
        await skipTo(s, pn);
        await step(s, theirs);
      }
      await skipTo(s, n);
      if (s.ckr === null || n < s.nr) return null; // a repeat of one we already opened
      const [key, next] = await kdfCk(s.ckr);
      mk = key;
      s.ckr = next;
      s.nr += 1;
    }
    const plain = copy(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aadFor(roomId, header) }, await messageKey(mk), ct),
    );
    const msg = unpackMessage(plain, from, 2);
    if (!msg) return null;
    return { state: s, msg };
  } catch {
    return null;
  }
}

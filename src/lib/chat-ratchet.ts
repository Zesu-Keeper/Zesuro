// Forward secrecy for private chat: a Double Ratchet (the scheme Signal uses) with a post-quantum layer, built
// from WebCrypto and the audited @noble ML-KEM.
//
// Every message is locked with its own key, and each key is erased as soon as it has been used. The two sides
// keep swapping fresh keys of two kinds as they reply:
//   - Diffie-Hellman keys (P-256), as in Signal;
//   - post-quantum keys (ML-KEM-768): each side announces a fresh one, and the other side locks a fresh secret to it
//     whenever it starts a new run of messages. Both secrets are mixed into the root key at every step.
// So: someone who gets hold of a device or its keys later can't open messages already sent; the chat protects
// itself again after a brief compromise; and scrambled copies recorded today stay safe even against a future
// quantum computer, which could break the Diffie-Hellman part but not ML-KEM.
//
// HKDF-SHA256 for the root and chain keys, HMAC-SHA256 to step a chain, AES-256-GCM per message. Pure functions: a
// state goes in and a new state comes out, so a message that fails to open never leaves the state half changed.
//
// Wire format (base64url of):
//   03 | pn u32 | n u32 | sender's DH key (65) | sender's ML-KEM public key (1184) | flag (1) | [ML-KEM ciphertext (1088)] | iv (12) | ciphertext
// The header is bound to the message as authenticated data. The server sees it: it learns message counts it could
// already count, and public keys that look random.

import { ml_kem768 as KEM } from "@noble/post-quantum/ml-kem.js";
import {
  bytes,
  copy,
  fromB64u,
  hkdf,
  kemPair,
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
const VERSION = 3;
const DH_LEN = 65;
const KEM_PK = 1184;
const KEM_CT = 1088;
const FIXED = 1 + 4 + 4 + DH_LEN + KEM_PK + 1;
/** The most messages one side may be ahead of the other before we refuse (skipped keys are kept for late ones). */
export const MAX_SKIP = 2000;
const MAX_KEPT = 2000;

export interface RatchetState {
  v: 3;
  role: Role;
  /** Root key. */
  rk: string;
  /** Our current Diffie-Hellman pair: private half (JWK), public half (raw, base64url). */
  dhsPriv: JsonWebKey;
  dhsPub: string;
  /** The other side's current Diffie-Hellman public key. Null until we have heard from them (the side that opened the link). */
  dhr: string | null;
  /** Our current ML-KEM pair (base64url), announced in every message we send. */
  kemSk: string;
  kemPk: string;
  /** The other side's latest announced ML-KEM public key. */
  kemTheirs: string | null;
  /** The ML-KEM ciphertext that belongs to our current sending chain (sent with each of its messages). */
  kemCt: string | null;
  /** Sending and receiving chain keys. */
  cks: string | null;
  ckr: string | null;
  ns: number;
  nr: number;
  pn: number;
  /** Keys for messages that arrived late or out of order, by "<their DH key>:<number>". */
  skipped: Record<string, string>;
  /** Everything this side has sent. It is the running number inside each message. */
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

export { kemPair };

/** (root key, DH output, ML-KEM secret) -> (new root key, chain key) */
async function kdfRk(rk: string, dhOut: Bytes, kemSecret: Uint8Array | null): Promise<[string, string]> {
  const ikm = bytes(dhOut.length + (kemSecret?.length ?? 0));
  ikm.set(dhOut);
  if (kemSecret) ikm.set(kemSecret, dhOut.length);
  const out = await hkdf(ikm, fromB64u(rk), "zesuro:dr:root:v3", 512);
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
  const raw = await hkdf(fromB64u(mk), bytes(32), "zesuro:dr:message:v3", 256);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

const u32 = (n: number) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const readU32 = (b: Uint8Array, at: number) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;

function aadFor(roomId: string, header: Uint8Array): Bytes {
  const base = enc.encode(`zesuro:chat:v3:msg:${roomId}`);
  const out = bytes(base.length + header.length);
  out.set(base);
  out.set(header, base.length);
  return out;
}

/** The root key both sides start from: only the master the key exchange produced, for this room. */
export async function rootFromMaster(master: string, roomId: string): Promise<string> {
  return toB64u(await hkdf(fromB64u(master), bytes(0), `zesuro:dr:start:v3:${roomId}`, 256));
}

/** Locks a fresh secret to `theirPk`. */
function encapsulate(theirPk: string): { ct: string; ss: Uint8Array } {
  const e = KEM.encapsulate(fromB64u(theirPk));
  return { ct: toB64u(e.cipherText), ss: e.sharedSecret };
}

// ---------- starting ----------
/**
 * The person who made the link. They know the opener's Diffie-Hellman and ML-KEM public keys from the key exchange,
 * so they can send straight away.
 */
export async function startAsCreator(master: string, roomId: string, theirPub: string, theirKem: string): Promise<RatchetState> {
  const rk0 = await rootFromMaster(master, roomId);
  const mine = await genPair();
  const lock = encapsulate(theirKem);
  const [rk, cks] = await kdfRk(rk0, await dh(mine.priv, theirPub), lock.ss);
  const k = kemPair();
  return {
    v: 3, role: "a", rk, dhsPriv: mine.priv, dhsPub: mine.pub, dhr: theirPub,
    kemSk: k.sk, kemPk: k.pk, kemTheirs: theirKem, kemCt: lock.ct,
    cks, ckr: null, ns: 0, nr: 0, pn: 0, skipped: {}, sent: 0,
  };
}

/** The person who opened the link. They keep the key pairs they made for the exchange and wait for the first message. */
export async function startAsOpener(
  master: string,
  roomId: string,
  priv: JsonWebKey,
  pub: string,
  kem: { sk: string; pk: string },
): Promise<RatchetState> {
  const rk = await rootFromMaster(master, roomId);
  return {
    v: 3, role: "b", rk, dhsPriv: priv, dhsPub: pub, dhr: null,
    kemSk: kem.sk, kemPk: kem.pk, kemTheirs: null, kemCt: null,
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
  const ct = s.kemCt ? fromB64u(s.kemCt) : null;
  const header = new Uint8Array(FIXED + (ct ? KEM_CT : 0));
  header[0] = VERSION;
  header.set(u32(s.pn), 1);
  header.set(u32(s.ns), 5);
  header.set(fromB64u(s.dhsPub), 9);
  header.set(fromB64u(s.kemPk), 9 + DH_LEN);
  header[9 + DH_LEN + KEM_PK] = ct ? 1 : 0;
  if (ct) header.set(ct, FIXED);
  const iv = crypto.getRandomValues(bytes(12));
  const plain = packMessage(s.role, s.sent, body, 2);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aadFor(roomId, header) }, await messageKey(mk), plain),
  );
  const out = bytes(header.length + 12 + sealed.length);
  out.set(header);
  out.set(iv, header.length);
  out.set(sealed, header.length + 12);
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

/** A new run of messages from the other side: mix in both kinds of fresh secret, then start our own new run. */
async function step(s: RatchetState, theirDh: string, theirKem: string, kemCt: Uint8Array | null): Promise<void> {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhr = theirDh;
  // Their new run was locked to the ML-KEM key we announced; open it, then retire that key for a fresh one.
  const received = kemCt ? KEM.decapsulate(kemCt, fromB64u(s.kemSk)) : null;
  [s.rk, s.ckr] = await kdfRk(s.rk, await dh(s.dhsPriv, theirDh), received);
  const fresh = await genPair();
  s.dhsPriv = fresh.priv;
  s.dhsPub = fresh.pub;
  const k = kemPair();
  s.kemSk = k.sk;
  s.kemPk = k.pk;
  s.kemTheirs = theirKem;
  const lock = encapsulate(theirKem);
  s.kemCt = lock.ct;
  [s.rk, s.cks] = await kdfRk(s.rk, await dh(fresh.priv, theirDh), lock.ss);
}

/**
 * Opens one blob from the other side. Null if it is not a genuine, well-formed message from them (the state is
 * then untouched); otherwise the new state and the message. A blob this side sent itself cannot be opened: its
 * key is already gone, which is the point.
 */
export async function ratchetDecrypt(
  state: RatchetState,
  roomId: string,
  blob: string,
): Promise<{ state: RatchetState; msg: Message } | null> {
  try {
    const raw = fromB64u(blob);
    if (raw.length < FIXED + 12 + 16 || raw[0] !== VERSION) return null;
    const flag = raw[9 + DH_LEN + KEM_PK];
    if (flag !== 0 && flag !== 1) return null;
    const hlen = FIXED + (flag ? KEM_CT : 0);
    if (raw.length < hlen + 12 + 16) return null;
    const header = raw.slice(0, hlen);
    const pn = readU32(header, 1);
    const n = readU32(header, 5);
    const theirDh = toB64u(header.slice(9, 9 + DH_LEN));
    const theirKem = toB64u(header.slice(9 + DH_LEN, 9 + DH_LEN + KEM_PK));
    const kemCt = flag ? header.slice(FIXED, FIXED + KEM_CT) : null;
    if (n > 1_000_000_000 || pn > 1_000_000_000) return null;
    const iv = raw.slice(hlen, hlen + 12);
    const ct = raw.slice(hlen + 12);
    const s = clone(state);
    const from: Role = s.role === "a" ? "b" : "a";

    let mk: string;
    const stored = s.skipped[`${theirDh}:${n}`];
    if (stored !== undefined) {
      mk = stored;
      delete s.skipped[`${theirDh}:${n}`];
    } else {
      if (theirDh !== s.dhr) {
        await skipTo(s, pn);
        await step(s, theirDh, theirKem, kemCt);
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

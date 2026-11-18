// Private chat crypto. Runs in the browser (and in Node for the tests); nothing here ever
// runs on the server, and no key in this file is ever sent to it.
//
// The link:   /chat#i=<S>            S = 32 random bytes. Browsers never send what follows "#".
//   invite id   = SHA-256("…invite-id:" + S)             what the server files the link under
//   invite key  = HKDF(S, "…invite-key")                 AES-GCM, protects the key exchange
//
// Key exchange (ECDH P-256). The creator makes one key per allowed use of the link, so no two
// chats ever share a creator key, and deletes each private key as soon as its chat starts:
//   creator -> server:  hello = AES(invite key, [one public key per use])     when the link is made
//   opener  -> server:  join  = AES(invite key, opener's public key, slot)    when the link is used
//   master  = HKDF(ECDH shared secret, salt = S, info = room id + both public keys)
// The server never has S, so it can neither read the public keys nor swap in its own. Someone
// who steals the link later, or a creator device seized later, still can't read a chat that
// has started: its private key is gone.
//
// From master, per room:  one AES-GCM key for each direction, a token that proves to the
// server "I belong to this room", a binding value the source signs, and a safety code (120
// bits) both people can compare.
//
// The source is shown to the other person by a pseudonym that exists for this chat alone: a
// signing key derived from the device secret and the chat's id. Entry proofs use the key made
// for that one entry (lib/commit.ts), so a proof links one entry to one chat and nothing else.
//
// Messages are JSON, padded to a few fixed sizes, AES-GCM encrypted. Each carries its
// sender's running number, so a dropped, repeated or reordered message shows.

import { commitInput, contentString, type CommitContent } from "./commit";

const enc = new TextEncoder();
const dec = new TextDecoder();
const P = "zesuro:chat:v1:";

type Bytes = Uint8Array<ArrayBuffer>;
export type Role = "a" | "b"; // a = the source who made the link, b = whoever opened it

export interface PubJwk {
  kty: string;
  crv: string;
  x: string;
  y: string;
}

// ---------- encoding ----------
function bytes(n: number): Bytes {
  return new Uint8Array(new ArrayBuffer(n));
}
function copy(src: ArrayBuffer | Uint8Array): Bytes {
  const s = src instanceof Uint8Array ? src : new Uint8Array(src);
  const out = bytes(s.length);
  out.set(s);
  return out;
}
export function toB64u(buf: ArrayBuffer | Uint8Array): string {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function fromB64u(s: string): Bytes {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("bad encoding");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  const out = bytes(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function toHex(buf: ArrayBuffer | Uint8Array): string {
  return Array.from(buf instanceof Uint8Array ? buf : new Uint8Array(buf), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}
function random(n: number): Bytes {
  return crypto.getRandomValues(bytes(n));
}
async function sha256(s: string): Promise<Bytes> {
  return copy(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}
export async function sha256Hex(s: string): Promise<string> {
  return toHex(await sha256(s));
}
async function hkdf(ikm: Bytes, salt: Bytes, info: string): Promise<Bytes> {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return copy(
    await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) }, k, 256),
  );
}
const aesKey = (raw: Bytes) =>
  crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

async function seal(key: CryptoKey, aad: string, plain: Bytes): Promise<string> {
  const iv = random(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(aad) }, key, plain);
  const out = bytes(12 + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), 12);
  return toB64u(out);
}
async function open(key: CryptoKey, aad: string, blob: string): Promise<Bytes | null> {
  try {
    const raw = fromB64u(blob);
    if (raw.length < 28) return null;
    return copy(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: raw.slice(0, 12), additionalData: enc.encode(aad) },
        key,
        raw.slice(12),
      ),
    );
  } catch {
    return null;
  }
}

// ---------- the link ----------
const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;
const SECRET_RE = /^[A-Za-z0-9_-]{43}$/;
/** A link opens at most this many chats, however many it was made for. */
export const MAX_USES = 100;

export function parseInviteFragment(hash: string): string | null {
  const m = /^#?i=([A-Za-z0-9_-]{43})$/.exec(hash.trim());
  return m ? m[1] : null;
}
export const inviteFragment = (secret: string) => `i=${secret}`;

export async function inviteIdOf(secret: string): Promise<string> {
  if (!SECRET_RE.test(secret)) throw new Error("That is not a chat link");
  return sha256Hex(`${P}invite-id:${secret}`);
}
async function inviteKey(secret: string): Promise<CryptoKey> {
  return aesKey(await hkdf(fromB64u(secret), bytes(0), `${P}invite-key`));
}

export interface NewInvite {
  /** Goes in the link, after "#". */
  secret: string;
  id: string;
  /** Proves to the server that this browser made the link. Never shared. */
  ownerSecret: string;
  /** What the server stores instead of ownerSecret. */
  ownerHash: string;
  /** One private key per use of the link. A slot becomes null once its chat has started. */
  privs: (JsonWebKey | null)[];
  hello: string;
  uses: number;
}

/** `maxUses` 0 means "as many as allowed" (MAX_USES). */
export async function newInvite(maxUses: number): Promise<NewInvite> {
  const uses = maxUses === 0 ? MAX_USES : Math.min(Math.max(Math.floor(maxUses), 1), MAX_USES);
  const secret = toB64u(random(32));
  const id = await inviteIdOf(secret);
  const ownerSecret = toHex(random(32));
  const pubs: string[] = [];
  const privs: JsonWebKey[] = [];
  for (let i = 0; i < uses; i++) {
    const pair = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
    pubs.push(toB64u(await crypto.subtle.exportKey("raw", pair.publicKey)));
    privs.push(await crypto.subtle.exportKey("jwk", pair.privateKey));
  }
  return {
    secret,
    id,
    ownerSecret,
    ownerHash: await sha256Hex(ownerSecret),
    privs,
    uses,
    hello: await seal(await inviteKey(secret), `hello:${id}`, enc.encode(JSON.stringify({ pubs }))),
  };
}

async function master(
  shared: ArrayBuffer,
  secret: string,
  roomId: string,
  pubA: string,
  pubB: string,
): Promise<string> {
  return toB64u(await hkdf(copy(shared), fromB64u(secret), `${P}master:${roomId}:${pubA}:${pubB}`));
}
const importPub = (raw: string) => crypto.subtle.importKey("raw", fromB64u(raw), ECDH, false, []);

function newRoomId(): string {
  const b = random(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = toHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** The person opening the link, using creator key number `slot`. */
export async function joinWith(
  secret: string,
  hello: string,
  slot: number,
): Promise<{ roomId: string; join: string; master: string; authHash: string }> {
  const id = await inviteIdOf(secret);
  const ik = await inviteKey(secret);
  const h = await open(ik, `hello:${id}`, hello);
  if (!h) throw new Error("This link does not match what the server holds. Do not use it.");
  const pubs = (JSON.parse(dec.decode(h)) as { pubs?: unknown }).pubs;
  if (!Array.isArray(pubs) || !Number.isInteger(slot) || slot < 0 || slot >= pubs.length || typeof pubs[slot] !== "string")
    throw new Error("This link can't be opened any more.");
  const pubA = pubs[slot] as string;
  const pair = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
  const pubB = toB64u(await crypto.subtle.exportKey("raw", pair.publicKey));
  const roomId = newRoomId();
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: await importPub(pubA) },
    pair.privateKey,
    256,
  );
  const m = await master(shared, secret, roomId, pubA, pubB);
  const keys = await roomKeys(m, roomId);
  return {
    roomId,
    join: await seal(ik, `join:${id}:${slot}`, enc.encode(JSON.stringify({ pub: pubB, room: roomId, a: pubA, slot }))),
    master: m,
    authHash: await sha256Hex(keys.token),
  };
}

/** The link's creator, for each room the server reports. Null if the join blob is not genuine. */
export async function acceptJoin(
  secret: string,
  priv: JsonWebKey | null,
  roomId: string,
  join: string,
  slot: number,
): Promise<string | null> {
  try {
    if (!priv) return null;
    const id = await inviteIdOf(secret);
    const j = await open(await inviteKey(secret), `join:${id}:${slot}`, join);
    if (!j) return null;
    const p = JSON.parse(dec.decode(j)) as { pub?: string; room?: string; a?: string; slot?: number };
    if (typeof p.pub !== "string" || p.room !== roomId || typeof p.a !== "string" || p.slot !== slot) return null;
    const mine = await crypto.subtle.importKey("jwk", priv, ECDH, true, ["deriveBits"]);
    // The opener says which public key they used for us: it must be this slot's.
    const jwk = await crypto.subtle.exportKey("jwk", mine);
    const pubKey = await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
      ECDH,
      true,
      [],
    );
    const pubA = toB64u(await crypto.subtle.exportKey("raw", pubKey));
    if (p.a !== pubA) return null;
    const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: await importPub(p.pub) }, mine, 256);
    return await master(shared, secret, roomId, pubA, p.pub);
  } catch {
    return null;
  }
}

// ---------- a room ----------
export interface RoomKeys {
  a2b: CryptoKey;
  b2a: CryptoKey;
  /** Sent to the server in x-chat-auth. Lets it hand over blobs; decrypts nothing. */
  token: string;
  /** The source signs this, tying their pseudonym to this one encrypted channel. */
  bind: string;
  /** Both people see the same code. If they differ, someone is in the middle. */
  safety: string;
}

const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function base32(b: Uint8Array, chars: number): string {
  let bits = 0n;
  for (const x of b) bits = (bits << 8n) | BigInt(x);
  const total = BigInt(b.length * 8);
  let out = "";
  for (let i = 0; i < chars; i++) out += B32[Number((bits >> (total - 5n * BigInt(i + 1))) & 31n)];
  return out;
}

export async function roomKeys(masterB64: string, roomId: string): Promise<RoomKeys> {
  const m = fromB64u(masterB64);
  if (m.length !== 32) throw new Error("bad chat key");
  const sub = (label: string) => hkdf(m, bytes(0), `${P}${label}:${roomId}`);
  // 24 characters of base32 = 120 bits: too many to find a second key pair that shows the same code.
  const code = base32((await sub("safety")).slice(0, 15), 24);
  return {
    a2b: await aesKey(await sub("a2b")),
    b2a: await aesKey(await sub("b2a")),
    token: toHex(await sub("auth")),
    bind: toHex(await sub("bind")),
    safety: code.match(/.{4}/g)!.join(" "),
  };
}

export type Body =
  /** The source's pseudonym for this chat, signed for this chat. */
  | { kind: "id"; pub: string; sig: string }
  | { kind: "text"; text: string }
  /** The key and salt of one public entry, and a signature made with that key for this chat. */
  | { kind: "proof"; uid: string; pub: string; salt: string; sig: string }
  | { kind: "timer"; ttl: number };

export type Message = Body & {
  v: 1;
  from: Role;
  /** This sender's running number, starting at 0. */
  n: number;
  /** The sender's clock. */
  t: number;
};

const SIZES = [1024, 2048, 4096, 8192, 16384, 32768];
export const MAX_TEXT = 4000;
export const TIMER_CHOICES = [0, 86_400_000, 7 * 86_400_000, 30 * 86_400_000];
const PUBX = /^[A-Za-z0-9_-]{43}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export async function encryptMessage(
  keys: RoomKeys,
  roomId: string,
  from: Role,
  n: number,
  body: Body,
): Promise<string> {
  // The clock is rounded to the minute: exact times would show a device's clock error.
  const json = enc.encode(JSON.stringify({ v: 1, from, n, t: Math.floor(Date.now() / 60_000) * 60_000, ...body }));
  const size = SIZES.find((s) => s >= json.length + 4);
  if (!size) throw new Error("That message is too long");
  const padded = bytes(size);
  new DataView(padded.buffer).setUint32(0, json.length);
  padded.set(json, 4);
  return seal(from === "a" ? keys.a2b : keys.b2a, `msg:${roomId}`, padded);
}

/** Accepts only well-formed messages: the other person holds a key too and could send junk. */
function validBody(m: Record<string, unknown>): boolean {
  switch (m.kind) {
    case "text":
      return typeof m.text === "string" && m.text.length > 0 && m.text.length <= MAX_TEXT * 2;
    case "id":
      return typeof m.pub === "string" && PUBX.test(m.pub) && typeof m.sig === "string" && m.sig.length <= 100;
    case "proof":
      return (
        typeof m.uid === "string" && UUID_RE.test(m.uid) &&
        typeof m.pub === "string" && PUBX.test(m.pub) &&
        typeof m.salt === "string" && /^[0-9a-f]{64}$/.test(m.salt) &&
        typeof m.sig === "string" && m.sig.length <= 100
      );
    case "timer":
      return typeof m.ttl === "number" && TIMER_CHOICES.includes(m.ttl);
    default:
      return false;
  }
}

/** Null if the blob was not made by one of the two people in this room, was altered, or is malformed. */
export async function decryptMessage(keys: RoomKeys, roomId: string, blob: string): Promise<Message | null> {
  for (const from of ["a", "b"] as const) {
    const padded = await open(from === "a" ? keys.a2b : keys.b2a, `msg:${roomId}`, blob);
    if (!padded) continue;
    try {
      const len = new DataView(padded.buffer).getUint32(0);
      if (len > padded.length - 4) return null;
      const m = JSON.parse(dec.decode(padded.slice(4, 4 + len))) as Record<string, unknown>;
      // The key that opened it says who sent it; the message must agree.
      if (m.v !== 1 || m.from !== from) return null;
      if (!Number.isSafeInteger(m.n) || (m.n as number) < 0 || (m.n as number) > 1_000_000_000) return null;
      if (typeof m.t !== "number" || !Number.isFinite(m.t)) return null;
      if (!validBody(m)) return null;
      return m as unknown as Message;
    } catch {
      return null;
    }
  }
  return null;
}

// ---------- who the source is, without saying who they are ----------
const PKCS8_ED25519 = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * The source's identity in one chat: a key derived from their device secret and the chat's id.
 * It is the same every time they open this chat and unrelated to any other chat or any entry.
 */
export async function chatIdentity(deviceSecret: Uint8Array, roomId: string): Promise<{ pubX: string; sign: CryptoKey }> {
  const hk = await crypto.subtle.importKey("raw", copy(deviceSecret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const seed = new Uint8Array(await crypto.subtle.sign("HMAC", hk, enc.encode(`whenisaid:chat-id:v2:${roomId}`)));
  const pkcs8 = bytes(PKCS8_ED25519.length + 32);
  pkcs8.set(PKCS8_ED25519);
  pkcs8.set(seed, PKCS8_ED25519.length);
  const tmp = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", tmp);
  return { pubX: jwk.x!, sign: await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]) };
}

/** A short name for a chat pseudonym. Nothing about it appears outside this chat. */
export async function pseudonymOf(pubX: string): Promise<string> {
  const s = base32((await sha256(`zesuro:chat-pseudonym:v2:${pubX}`)).slice(0, 10), 16);
  return `ZS-${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}-${s.slice(12)}`;
}

const idMessage = (roomId: string, bind: string) => enc.encode(`whenisaid:chat-id:v2:${roomId}:${bind}`);
const proofMessage = (roomId: string, bind: string, uid: string) =>
  enc.encode(`whenisaid:chat-proof:v2:${roomId}:${bind}:${uid}`);

async function edVerify(pubX: string, sig: string, msg: Uint8Array<ArrayBuffer>): Promise<boolean> {
  try {
    if (!PUBX.test(pubX)) return false;
    const k = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: pubX }, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, k, fromB64u(sig), msg);
  } catch {
    return false;
  }
}

export async function signIdentity(sign: CryptoKey, roomId: string, bind: string): Promise<string> {
  return toB64u(await crypto.subtle.sign({ name: "Ed25519" }, sign, idMessage(roomId, bind)));
}
export const verifyIdentity = (pubX: string, sig: string, roomId: string, bind: string) =>
  edVerify(pubX, sig, idMessage(roomId, bind));

/** Signed with the entry's own key: shows the signer holds it now, in this chat. */
export async function signProof(sign: CryptoKey, roomId: string, bind: string, uid: string): Promise<string> {
  return toB64u(await crypto.subtle.sign({ name: "Ed25519" }, sign, proofMessage(roomId, bind, uid)));
}
export const verifyProofSig = (pubX: string, sig: string, roomId: string, bind: string, uid: string) =>
  edVerify(pubX, sig, proofMessage(roomId, bind, uid));

/**
 * True if `pubX` and `salt` open the entry's public commitment for exactly the content shown:
 * this key sealed this text.
 */
export async function proofMatches(
  pubX: string,
  salt: string,
  content: CommitContent,
  commitment: string,
): Promise<boolean> {
  if (!/^[0-9a-f]{64}$/.test(salt) || !PUBX.test(pubX)) return false;
  return (await sha256Hex(commitInput(pubX, salt, await sha256Hex(contentString(content))))) === commitment;
}

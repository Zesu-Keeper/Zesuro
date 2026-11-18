/**
 * Moving your keys to another Zesuro address.
 *
 * A browser keeps its keys per address (localStorage), so a second domain or a replacement
 * server starts with none: your entries would not show under "Mine" and your chats would not
 * open. This makes one encrypted bundle of everything this browser holds for Zesuro, and
 * opens it on the other address. Nothing is sent to any server: the bundle is text that you
 * carry yourself, and the code that opens it is a separate secret that you carry another way.
 *
 * Format: "ZT1." + salt + "." + iv + "." + ciphertext (base64url).
 * Key: HKDF-SHA256(code, salt, "zesuro:transfer:v1") -> AES-256-GCM, with the same label as AAD.
 * The code is 120 random bits (24 base32 characters), never a password a person chose, so a
 * stolen bundle cannot be guessed at offline.
 */

/** Every browser-storage key the app keeps; the bundle only ever carries these. */
export const TRANSFER_KEYS = [
  "whenisaid.key.v1", // the device key: authorship of everything you posted
  "whenisaid.mine.v1",
  "whenisaid.chats.v1", // private chat keys
  "whenisaid.threads.v1", // informant thread keys
  "whenisaid.voter.v2",
  "whenisaid.votes.v1",
  "whenisaid.outcomes.v1",
  "whenisaid.reported.v1",
  "whenisaid.backedup.v1",
] as const;

const LABEL = "zesuro:transfer:v1";
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const MAX_BUNDLE = 4_000_000;
const MAX_VALUE = 2_000_000;
const enc = new TextEncoder();

function b64u(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000)); // chunked: big bundles overflow a single spread
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64u(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("not a transfer bundle");
  const p = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(p), (c) => c.charCodeAt(0));
}
// WebCrypto wants plain ArrayBuffers; copying avoids any view-offset surprises.
const buf = (u: Uint8Array): ArrayBuffer => u.slice().buffer as ArrayBuffer;

/** A fresh code, shown as XXXX-XXXX-XXXX-XXXX-XXXX-XXXX. */
export function makeCode(): string {
  const raw = crypto.getRandomValues(new Uint8Array(24));
  const chars = Array.from(raw, (b) => ALPHABET[b % 32]); // 256 is a multiple of 32, so no bias
  return chars.join("").replace(/(.{4})(?=.)/g, "$1-");
}

/** Accepts the code however it was typed or pasted; null if it cannot be a code. */
export function normaliseCode(input: string): string | null {
  const s = input.toUpperCase().replace(/[\s-]/g, "");
  return /^[A-Z2-7]{24}$/.test(s) ? s : null;
}

async function keyFor(code: string, salt: Uint8Array): Promise<CryptoKey> {
  const norm = normaliseCode(code);
  if (!norm) throw new Error("That is not a transfer code");
  const base = await crypto.subtle.importKey("raw", buf(enc.encode(norm)), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: buf(salt), info: buf(enc.encode(LABEL)) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Encrypts the given storage items (only allowed keys are kept) under `code`. */
export async function sealBundle(items: Record<string, string>, code: string): Promise<string> {
  const kept: Record<string, string> = {};
  for (const k of TRANSFER_KEYS) if (typeof items[k] === "string") kept[k] = items[k];
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ v: 1, at: Date.now(), items: kept }));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: buf(iv), additionalData: buf(enc.encode(LABEL)) }, await keyFor(code, salt), buf(plain)),
  );
  return `ZT1.${b64u(salt)}.${b64u(iv)}.${b64u(ct)}`;
}

/** Decrypts a bundle. Throws "wrong code or damaged bundle" without saying which. */
export async function openBundle(text: string, code: string): Promise<Record<string, string>> {
  const t = text.trim();
  if (t.length > MAX_BUNDLE) throw new Error("not a transfer bundle");
  const p = t.split(".");
  if (p.length !== 4 || p[0] !== "ZT1") throw new Error("not a transfer bundle");
  const salt = unb64u(p[1]), iv = unb64u(p[2]), ct = unb64u(p[3]);
  if (salt.length !== 16 || iv.length !== 12 || ct.length < 16) throw new Error("not a transfer bundle");
  let plain: ArrayBuffer;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf(iv), additionalData: buf(enc.encode(LABEL)) }, await keyFor(code, salt), buf(ct));
  } catch (e) {
    if (e instanceof Error && e.message === "That is not a transfer code") throw e;
    throw new Error("Wrong code, or the bundle is damaged");
  }
  const j = JSON.parse(new TextDecoder().decode(plain));
  if (j?.v !== 1 || typeof j.items !== "object" || j.items === null) throw new Error("not a transfer bundle");
  const out: Record<string, string> = {};
  for (const k of TRANSFER_KEYS) {
    const v = j.items[k];
    if (v === undefined) continue;
    if (typeof v !== "string" || v.length > MAX_VALUE) throw new Error("not a transfer bundle");
    out[k] = v;
  }
  return out;
}

export interface ImportPlan {
  /** Absent here: will be added. */
  add: string[];
  /** Already identical here: nothing to do. */
  same: string[];
  /** Present here and different: kept as they are, never overwritten. */
  keep: string[];
  /** True if the device key differs: the two browsers are two different people, so importing is refused. */
  deviceKeyConflict: boolean;
}

/** What importing would do. Existing values are never overwritten. */
export function planImport(existing: Record<string, string | null>, incoming: Record<string, string>): ImportPlan {
  const plan: ImportPlan = { add: [], same: [], keep: [], deviceKeyConflict: false };
  for (const [k, v] of Object.entries(incoming)) {
    const have = existing[k] ?? null;
    if (have === null) plan.add.push(k);
    else if (have === v) plan.same.push(k);
    else plan.keep.push(k);
  }
  plan.deviceKeyConflict = plan.keep.includes("whenisaid.key.v1");
  return plan;
}

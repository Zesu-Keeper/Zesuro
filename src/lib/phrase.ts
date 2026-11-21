// Six-word keys: a device key you can carry in your head or on a slip of paper, instead of a QR code.
//
// The six words come from a list of 2048, so they hold 66 bits, which is a lot for a guess-by-guess attack when
// every guess has to run a slow, memory-hungry hash (Argon2id). The key is made from the words alone. The same
// six words give the same key on any device, so they are also the backup: nothing else has to be saved.
//
// Only ever use words this page gave you. Words you choose yourself are far easier to guess.

import { argon2idAsync } from "@noble/hashes/argon2.js";
import { p256 } from "@noble/curves/nist.js";
import { buildKey, bytesToB64u, type StoredKey } from "./client-crypto";
import { WORDS } from "./wordlist";

export const WORD_COUNT = 6;
/** Slow on purpose: a guess costs about a second and 32 MB, so trying many phrases is very expensive. */
export const PHRASE_COST = { t: 3, m: 32768, p: 1 } as const;
const SALT = new TextEncoder().encode("zesuro:six-word-key:v1");
const INDEX = new Map(WORDS.map((w, i) => [w, i]));

/** Six random words. 2048 is a power of two, so taking 11 bits per word is unbiased. */
export function makePhrase(): string[] {
  const r = crypto.getRandomValues(new Uint16Array(WORD_COUNT));
  return Array.from(r, (v) => WORDS[v & 0x7ff]);
}

/** Reads what someone typed: any case, spaces, commas or dashes between words. Null if it is not six listed words. */
export function readPhrase(text: string): string[] | null {
  const w = text.toLowerCase().split(/[\s,;.\-_]+/).filter(Boolean);
  if (w.length !== WORD_COUNT) return null;
  return w.every((x) => INDEX.has(x)) ? w : null;
}

const toBig = (b: Uint8Array) => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);

/** The device key these six words make. Takes a second or two. */
export async function phraseToKey(words: string[]): Promise<StoredKey> {
  if (words.length !== WORD_COUNT || !words.every((x) => INDEX.has(x))) throw new Error("Those are not six words from the list");
  const raw = await argon2idAsync(new TextEncoder().encode(words.join(" ")), SALT, { ...PHRASE_COST, dkLen: 48 });
  // 48 bytes reduced mod (n - 1), plus one, is a valid private scalar with no noticeable bias.
  const n = p256.Point.Fn.ORDER;
  const d = (toBig(raw) % (n - 1n)) + 1n;
  const dBytes = Uint8Array.from({ length: 32 }, (_, i) => Number((d >> BigInt(8 * (31 - i))) & 0xffn));
  const pub = p256.getPublicKey(dBytes, false);
  return buildKey(bytesToB64u(dBytes), bytesToB64u(pub.slice(1, 33)), bytesToB64u(pub.slice(33, 65)));
}

/**
 * A short code that shows which key a set of words makes, so a typing mistake is caught: the code shown when the words
 * were made must match the code shown when they are typed again. It reveals almost nothing about the key.
 */
export async function keyCheckCode(k: StoredKey): Promise<string> {
  const text = JSON.stringify({ crv: k.pub.crv, kty: k.pub.kty, x: k.pub.x, y: k.pub.y });
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("zesuro:key-check:v1:" + text)));
  return Array.from(h.slice(0, 2), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

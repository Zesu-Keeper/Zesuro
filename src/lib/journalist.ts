// Browser only. A journalist's identity for private replies: an Ed25519 key whose public half the journalist's
// newsroom publishes at https://<newsroom>/.well-known/zesuro-journalists.json, for example
//   { "journalists": [ { "name": "Jane Doe", "key": "<public key>" } ] }
// A reply signed with that key shows the author "Verified: Jane Doe at example.org". The signature covers the post,
// the chat link it offers and the text, so it can't be moved to another reply.

import { b64u, unb64u } from "./mailbox";

const STORE = "whenisaid.journalist.v1";
const enc = new TextEncoder();
const PKCS8_ED25519 = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

export interface JournalistId {
  name: string;
  domain: string;
  /** Ed25519 private seed and public key, base64url. */
  seed: string;
  key: string;
}

export const DOMAIN = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function loadJournalist(): JournalistId | null {
  try {
    const j = JSON.parse(localStorage.getItem(STORE) || "null") as JournalistId | null;
    return j && typeof j.seed === "string" && typeof j.key === "string" ? j : null;
  } catch {
    return null;
  }
}

async function signer(seed: string): Promise<CryptoKey> {
  const pk = new Uint8Array(PKCS8_ED25519.length + 32);
  pk.set(PKCS8_ED25519);
  pk.set(unb64u(seed), PKCS8_ED25519.length);
  return crypto.subtle.importKey("pkcs8", pk, { name: "Ed25519" }, true, ["sign"]);
}

export async function createJournalist(name: string, domain: string): Promise<JournalistId> {
  const seed = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const k = await signer(seed);
  const jwk = await crypto.subtle.exportKey("jwk", k);
  const id: JournalistId = { name: name.trim().slice(0, 80), domain: domain.trim().toLowerCase(), seed, key: jwk.x! };
  localStorage.setItem(STORE, JSON.stringify(id));
  return id;
}

export function forgetJournalist() {
  try {
    localStorage.removeItem(STORE);
  } catch {
    /* nothing kept */
  }
}

const sha256hex = async (s: string) =>
  Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))), (b) => b.toString(16).padStart(2, "0")).join("");
const message = async (uid: string, invite: string, text: string, domain: string, name: string) =>
  enc.encode(`zesuro:journalist-reply:v1:${uid}:${await sha256hex(invite)}:${await sha256hex(text)}:${domain}:${name}`);

export async function signReply(id: JournalistId, uid: string, invite: string, text: string) {
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, await signer(id.seed), await message(uid, invite, text, id.domain, id.name));
  return { name: id.name, domain: id.domain, key: id.key, sig: b64u(new Uint8Array(sig)) };
}

export async function verifyReplySig(
  from: { name: string; domain: string; key: string; sig: string },
  uid: string,
  invite: string,
  text: string,
): Promise<boolean> {
  try {
    const k = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: from.key }, { name: "Ed25519" }, false, ["verify"]);
    const sig = new Uint8Array(unb64u(from.sig));
    return await crypto.subtle.verify({ name: "Ed25519" }, k, sig, await message(uid, invite, text, from.domain, from.name));
  } catch {
    return false;
  }
}

/** True if the newsroom at `domain` lists `key` under `name` (fetched through the site, which checks the address). */
export async function newsroomLists(domain: string, key: string, name: string, base = ""): Promise<boolean> {
  try {
    const r = await fetch(`${base}/api/newsroom?domain=${encodeURIComponent(domain)}`, { cache: "no-store" });
    if (!r.ok) return false;
    const d = (await r.json()) as { journalists?: { name?: unknown; key?: unknown }[] };
    return (d.journalists ?? []).some((j) => j.key === key && j.name === name);
  } catch {
    return false;
  }
}

/** The line a journalist's newsroom adds to its well-known file. */
export const listingFor = (id: JournalistId) => JSON.stringify({ journalists: [{ name: id.name, key: id.key }] }, null, 2);

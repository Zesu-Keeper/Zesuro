import { createHash, webcrypto } from "node:crypto";
import { commitInput, contentString, revealMessageV2, type CommitContent } from "./commit";
import { hasHiddenControls } from "./text";

// Proof of authorship ("opening"). Each entry stores only
//   commitment = SHA-256( canonicalPub + ":" + salt )
// where salt is derived from the author's private key and the entry's public nonce.
// Because the salt differs per entry, entries from one key cannot be linked until opened.

const subtle = webcrypto.subtle;

export interface Opening {
  /** 2 = per-entry Ed25519 key and a commitment that covers the entry's content. Absent = v1. */
  v?: 2;
  pub: { kty: string; crv: string; x: string; y?: string };
  salt: string; // 64 hex chars
  handle: string;
  sig: string; // base64url ECDSA P-256 / SHA-256 (raw r||s)
}

export const HEX64 = /^[0-9a-f]{64}$/;
export const HEX32 = /^[0-9a-f]{32}$/;
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

export function canonicalPub(p: Opening["pub"]): string {
  return JSON.stringify({ crv: p.crv, kty: p.kty, x: p.x, y: p.y });
}

export function normalizeHandle(h: unknown): string | null {
  if (typeof h !== "string") return null;
  const t = h.trim().replace(/\s+/g, " ");
  if (t.length < 1 || t.length > 40) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(t) || hasHiddenControls(t)) return null;
  return t;
}

export function revealMessage(uid: string, handle: string): string {
  return `whenisaid:reveal:v1:${uid}:${handle}`;
}

function b64uToBytes(s: string): Uint8Array<ArrayBuffer> {
  const buf = Buffer.from(s, "base64url");
  const out = new Uint8Array(new ArrayBuffer(buf.length));
  out.set(buf);
  return out;
}

export function parseOpening(raw: unknown): Opening | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  const p = o.pub as Record<string, unknown> | undefined;
  if (!p) return null;
  if (typeof o.salt !== "string" || !HEX64.test(o.salt)) return null;
  if (typeof o.sig !== "string" || o.sig.length > 200) return null;
  const handle = normalizeHandle(o.handle);
  if (!handle) return null;
  if (o.v === 2) {
    if (p.kty !== "OKP" || p.crv !== "Ed25519") return null;
    if (typeof p.x !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(p.x)) return null;
    return { v: 2, pub: { kty: "OKP", crv: "Ed25519", x: p.x }, salt: o.salt, handle, sig: o.sig };
  }
  if (o.v !== undefined) return null;
  if (p.kty !== "EC" || p.crv !== "P-256") return null;
  if (typeof p.x !== "string" || typeof p.y !== "string") return null;
  return {
    pub: { kty: "EC", crv: "P-256", x: p.x, y: p.y },
    salt: o.salt,
    handle,
    sig: o.sig,
  };
}

/**
 * Does this opening prove its key made `commitment`? `commitV` is the entry's stored version:
 * v2 openings must match a v2 entry and are checked against the entry's content, v1 against v1.
 */
export async function verifyOpening(
  uid: string,
  commitment: string,
  op: Opening,
  commitV: number,
  content?: CommitContent,
): Promise<boolean> {
  if ((op.v === 2) !== (commitV === 2)) return false;
  if (op.v === 2) {
    if (!content || content.uid !== uid) return false;
    const want = sha256Hex(commitInput(op.pub.x, op.salt, sha256Hex(contentString(content))));
    if (want !== commitment) return false;
    try {
      const key = await subtle.importKey(
        "jwk",
        { kty: "OKP", crv: "Ed25519", x: op.pub.x },
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      return await subtle.verify(
        { name: "Ed25519" },
        key,
        b64uToBytes(op.sig),
        new TextEncoder().encode(revealMessageV2(uid, op.handle)),
      );
    } catch {
      return false;
    }
  }
  if (sha256Hex(`${canonicalPub(op.pub)}:${op.salt}`) !== commitment) return false;
  try {
    const key = await subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: op.pub.x, y: op.pub.y, ext: true, key_ops: ["verify"] },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      b64uToBytes(op.sig),
      new TextEncoder().encode(revealMessage(uid, op.handle)),
    );
  } catch {
    return false;
  }
}

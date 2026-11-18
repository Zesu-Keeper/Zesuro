import { createHash, createPublicKey, verify } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { getDb } from "./db";
import { EntryError } from "./errors";

// Signed chain tips, countersigned by independent witnesses. No outside service is involved.
//   head   the exact text that was signed: a small JSON document holding the time, the number
//          of entries and comments and the hash at the tip of each chain. scripts/anchor.mjs
//          makes one every few minutes when something has changed.
//   sig    this site's Ed25519 signature over head.
//   witnesses   mirrors run by other people (scripts/mirror.mjs --witness). A witness fetches
//          the anchor, checks it against its own complete copy of the record, and signs
//              "zesuro:witness:v1:" + SHA-256(head) + ":" + the time it saw it
//          It refuses if the record it holds was changed. So a witnessed anchor says: at that
//          time, someone other than this site held this exact record. Rewriting an entry
//          afterwards changes every hash after it, including the tips the witnesses signed.
// The operator decides which witness keys count (scripts/admin.mjs witness-add).

export interface AnchorRow {
  id: number;
  at: number;
  head: string;
  sig: string;
}
export interface Witness {
  key: string;
  name: string;
  at: number;
  sig: string;
}

const KEY = /^[A-Za-z0-9_-]{43}$/;
export const witnessMessage = (head: string, at: number) =>
  `zesuro:witness:v1:${createHash("sha256").update(head).digest("hex")}:${at}`;

export function listAnchors(before: number, limit: number) {
  const db = getDb();
  const rows = db
    .prepare("SELECT id, at, head, sig FROM anchors WHERE id < ? ORDER BY id DESC LIMIT ?")
    .all(before > 0 ? before : Number.MAX_SAFE_INTEGER, Math.min(Math.max(Math.floor(limit) || 50, 1), 200)) as unknown as AnchorRow[];
  const ws = db.prepare(
    `SELECT w.key, k.name, w.at, w.sig FROM anchor_witnesses w JOIN witness_keys k ON k.key = w.key
      WHERE w.anchor_id = ? ORDER BY w.at`,
  );
  return rows.map((r) => ({
    id: r.id,
    at: r.at,
    head: JSON.parse(r.head),
    sig: r.sig,
    witnesses: ws.all(r.id) as unknown as Witness[],
  }));
}

export function getAnchor(id: number): AnchorRow | null {
  if (!Number.isSafeInteger(id) || id < 1) return null;
  return (getDb().prepare("SELECT id, at, head, sig FROM anchors WHERE id = ?").get(id) as unknown as AnchorRow | undefined) ?? null;
}

/** Records a witness's countersignature. Only keys the operator has accepted count. */
export function addWitness(id: number, input: Record<string, unknown>): { ok: true } {
  const a = getAnchor(id);
  if (!a) throw new EntryError("Anchor not found", 404);
  const { key, at, sig } = input;
  if (typeof key !== "string" || !KEY.test(key)) throw new EntryError("Invalid witness key");
  if (typeof sig !== "string" || sig.length > 100) throw new EntryError("Invalid signature");
  if (typeof at !== "number" || !Number.isSafeInteger(at)) throw new EntryError("Invalid time");
  const now = Date.now();
  // A witness can't have seen an anchor before it existed, or in the future.
  if (at < a.at - 300_000 || at > now + 300_000) throw new EntryError("That time is not possible for this anchor");
  const db = getDb();
  if (!db.prepare("SELECT 1 FROM witness_keys WHERE key = ?").get(key))
    throw new EntryError("This site does not know that witness. Send its key to the operator.", 403);
  let ok = false;
  try {
    ok = verify(
      null,
      Buffer.from(witnessMessage(a.head, at)),
      createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key }, format: "jwk" }),
      Buffer.from(sig, "base64url"),
    );
  } catch {
    ok = false;
  }
  if (!ok) throw new EntryError("That signature does not verify", 400);
  db.prepare("INSERT OR IGNORE INTO anchor_witnesses (anchor_id, key, at, sig) VALUES (?, ?, ?, ?)").run(id, key, at, sig);
  return { ok: true };
}

/** The public half of the site's signing key (raw Ed25519, base64url), if anchoring has run. */
export function anchorPublicKey(): string | null {
  try {
    return fs.readFileSync(path.join(process.cwd(), "data", "anchor-key.pub"), "utf8").trim() || null;
  } catch {
    return null;
  }
}

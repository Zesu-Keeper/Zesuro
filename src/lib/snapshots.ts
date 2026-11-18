import fs from "node:fs";
import path from "node:path";
import { createPublicKey, verify } from "node:crypto";
import { getDb } from "@/lib/db";
import { EntryError } from "@/lib/entries";

/**
 * Encrypted database snapshots (written by scripts/snapshot.mjs) for standby servers to keep.
 * The manifest (counts, tips, hash, the writer's signature) is public. The snapshot file is
 * encrypted to the recovery key, but it is handed only to standbys whose key the operator has
 * accepted (the same keys as accepted witnesses), because encryption that is strong today may not
 * stay strong, and nobody else has a reason to hold a copy.
 */
const dir = () => path.join(process.cwd(), "data", "snapshots");
const NAME = /^snapshot-\d{10,16}\.zsnap$/;
const KEY = /^[A-Za-z0-9_-]{43}$/;

export const snapshotRequestMessage = (name: string, at: number) => `zesuro:snapshot-get:v1:${name}:${at}`;

export function latestManifest(): string | null {
  try {
    return fs.readFileSync(path.join(dir(), "latest.json"), "utf8");
  } catch {
    return null;
  }
}

/** The path of a snapshot file, if the name is well formed and the file exists. */
export function snapshotPath(name: string): string | null {
  if (!NAME.test(name)) return null;
  const p = path.join(dir(), name);
  return fs.existsSync(p) ? p : null;
}

/** Checks the three x-zesuro-* headers: an accepted standby key, a fresh time, and its signature over this request. */
export function authoriseStandby(req: Request, name: string): void {
  const key = req.headers.get("x-zesuro-key") ?? "";
  const at = Number(req.headers.get("x-zesuro-at"));
  const sig = req.headers.get("x-zesuro-sig") ?? "";
  if (!KEY.test(key) || !Number.isSafeInteger(at) || sig.length > 100) throw new EntryError("Not authorised", 401);
  if (Math.abs(Date.now() - at) > 300_000) throw new EntryError("Not authorised", 401);
  if (!getDb().prepare("SELECT 1 FROM witness_keys WHERE key = ?").get(key)) throw new EntryError("Not authorised", 401);
  let ok = false;
  try {
    ok = verify(
      null,
      Buffer.from(snapshotRequestMessage(name, at)),
      createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key }, format: "jwk" }),
      Buffer.from(sig, "base64url"),
    );
  } catch {
    ok = false;
  }
  if (!ok) throw new EntryError("Not authorised", 401);
}

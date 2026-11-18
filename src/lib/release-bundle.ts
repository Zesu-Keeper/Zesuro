/**
 * What a time-locked entry carries: the author's opening and, if the entry has hidden parts, the
 * hidden parts. The browser makes this, encrypts it to the reveal round (timelock.ts) and sends only
 * the ciphertext; the server decrypts it when the round comes and checks it against the entry's
 * commitments. Shared by the browser and the server so both agree on the shape.
 */

/**
 * A bundle is a name, a proof and the hidden parts. The hidden parts are already capped at about 30 KB
 * (the author's encrypted backup of them, lib/entries.ts), so this allows the same.
 */
export const MAX_BUNDLE_BYTES = 32_000;

export interface ReleaseBundle {
  /** The author's opening (lib/opening.ts), unchecked: the server runs it through parseOpening. */
  opening: unknown;
  /** The hidden parts (lib/secret.ts), or null if the entry has none. Unchecked, likewise. */
  secret: unknown;
}

export function encodeBundle(b: ReleaseBundle): Uint8Array {
  const bytes = new TextEncoder().encode(JSON.stringify({ v: 1, opening: b.opening, secret: b.secret ?? null }));
  if (bytes.length > MAX_BUNDLE_BYTES) throw new Error("The hidden parts are too long to time-lock. Shorten them.");
  return bytes;
}

/** Strict: exactly version 1, an object for the opening, and nothing the server would have to guess at. */
export function decodeBundle(bytes: Uint8Array): ReleaseBundle {
  if (bytes.length > MAX_BUNDLE_BYTES) throw new Error("bundle too large");
  const j = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as Record<string, unknown> | null;
  if (!j || typeof j !== "object" || Array.isArray(j) || j.v !== 1) throw new Error("not a release bundle");
  if (!j.opening || typeof j.opening !== "object") throw new Error("the bundle has no opening");
  return { opening: j.opening, secret: j.secret ?? null };
}

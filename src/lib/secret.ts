import { HEX32, sha256Hex } from "./opening";
import { hasHiddenControls } from "./text";

// Redacted text and a hidden place are sealed as one "secret" payload. The public record holds
//   secretCommit = SHA-256( JSON.stringify([parts, place, salt]) )
// and the hash chain covers that commitment. The payload itself is published only when the
// entry is released, and anyone can then recompute the hash and compare.

/** Private-use character that marks where a redaction sits in the public text. */
export const REDACTION_MARK = "";

export interface Place {
  lat: number;
  lng: number;
  label: string;
}

export interface Secret {
  parts: string[];
  place: Place | null;
  salt: string; // 32 hex chars
}

export const MAX_PART = 2000;
export const MAX_LABEL = 80;

export function countRedactions(text: string): number {
  return text.split(REDACTION_MARK).length - 1;
}

export function secretCommitOf(s: Secret): string {
  return sha256Hex(JSON.stringify([s.parts, s.place, s.salt]));
}

const round5 = (n: number) => Math.round(n * 1e5) / 1e5;

/** Validates a place. Coordinates are rounded to 5 decimals (about 1 m). */
export function parsePlace(raw: unknown): Place | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  if (typeof o.lat !== "number" || typeof o.lng !== "number") return null;
  if (!Number.isFinite(o.lat) || !Number.isFinite(o.lng)) return null;
  if (o.lat < -90 || o.lat > 90 || o.lng < -180 || o.lng > 180) return null;
  const labelRaw = typeof o.label === "string" ? o.label : "";
  // eslint-disable-next-line no-control-regex
  const label = labelRaw.replace(/[\u0000-\u001f\u007f]/g, " ").trim().replace(/\s+/g, " ");
  if (label.length > MAX_LABEL || hasHiddenControls(label)) return null;
  return { lat: round5(o.lat), lng: round5(o.lng), label };
}

export function parseSecret(
  raw: unknown,
  redactions: number,
  needPlace: boolean,
): Secret | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  if (!Array.isArray(o.parts) || o.parts.length !== redactions) return null;
  let total = 0;
  for (const p of o.parts) {
    if (typeof p !== "string" || p.length === 0 || p.length > MAX_PART || hasHiddenControls(p))
      return null;
    total += p.length;
  }
  if (total > 5000) return null;
  if (typeof o.salt !== "string" || !HEX32.test(o.salt)) return null;
  let place: Place | null = null;
  if (needPlace) {
    place = parsePlace(o.place);
    if (!place) return null;
  } else if (o.place !== null && o.place !== undefined) {
    return null;
  }
  return { parts: o.parts as string[], place, salt: o.salt };
}

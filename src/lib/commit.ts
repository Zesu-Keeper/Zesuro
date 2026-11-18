// Entry commitments, version 2. Pure functions shared by the browser and the server.
//
//   commitment = SHA-256( "zesuro:commit:v2:" + entryKey + ":" + salt + ":" + SHA-256(content) )
//
// entryKey is a public key made for this one entry (derived from the author's secret and the
// entry's nonce), so no two entries from one author share a key. content is everything the
// author means to stand behind: the entry's id, title, text, public place, the commitment to
// its hidden parts and its mode. Because the commitment covers the content, a commitment can't
// be re-attached to different text, to a different entry, or to text the site has altered:
// the author's opening only verifies against exactly what they sealed.

export type PlaceModeC = "none" | "public" | "hidden";

export interface CommitContent {
  uid: string;
  title: string;
  /** The public text, with a redaction mark wherever something is redacted. */
  text: string;
  placeMode: PlaceModeC;
  /** Only used when placeMode is "public". */
  place: { lat: number; lng: number; label: string } | null;
  secretCommit: string | null;
  mode: "manual" | "date" | "locked";
}

export const COMMIT_V2 = "zesuro:commit:v2:";

export function contentString(c: CommitContent): string {
  return JSON.stringify([
    "zesuro:content:v2",
    c.uid,
    c.title,
    c.text,
    c.placeMode,
    c.placeMode === "public" && c.place ? [c.place.lat, c.place.lng, c.place.label] : null,
    c.secretCommit,
    c.mode,
  ]);
}

/** The string that is hashed into a commitment, given the hash of contentString(). */
export const commitInput = (entryKey: string, salt: string, contentHash: string) =>
  `${COMMIT_V2}${entryKey}:${salt}:${contentHash}`;

export const revealMessageV2 = (uid: string, handle: string) =>
  `whenisaid:reveal:v2:${uid}:${handle}`;

// Normalisation, applied identically by the browser (before committing) and the server.
export const normText = (s: string) => s.replace(/\r\n/g, "\n").trim();
// eslint-disable-next-line no-control-regex
export const normTitle = (s: string) => s.replace(/[\u0000-\u001f\u007f\ue000]/g, " ").trim().replace(/\s+/g, " ");

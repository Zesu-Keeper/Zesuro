import { randomBytes } from "node:crypto";
import { getDb } from "./db";
import { EntryError } from "./errors";
import {
  HEX32,
  HEX64,
  UUID,
  type Opening,
  parseOpening,
  sha256Hex,
  verifyOpening,
} from "./opening";
import {
  blockedDomainIn,
  countLinks,
  SPAM_CAP,
  dupHash,
  jaccard,
  MAX_LINKS_ENTRY,
  SIMILAR_AT,
  SIMILAR_MIN_WORDS,
  wordSet,
} from "./spam";
import { normText, normTitle, type CommitContent } from "./commit";
import { hasHiddenControls } from "./text";
import { assertRecordWritable } from "./writer";
import {
  countRedactions,
  parsePlace,
  parseSecret,
  secretCommitOf,
  type Place,
  type Secret,
} from "./secret";
import { getBeacon } from "./beacon";
import { decodeBundle } from "./release-bundle";
import { lockedRound, roundForTime, timeOfRound, timelockDecrypt } from "./timelock";

export type PlaceMode = "none" | "public" | "hidden";
export type Mode = "manual" | "date" | "locked";
export type Status = "anonymous" | "revealed" | "unknown";

export const MAX_TEXT = 5000;
const GENESIS = "0".repeat(64);

interface Row {
  seq: number;
  uid: string;
  text: string;
  commitment: string;
  nonce: string;
  created_at: number;
  mode: Mode;
  reveal_at: number | null;
  deadline_at: number | null;
  prev_hash: string;
  entry_hash: string;
  reveal_pkg: string | null;
  revealed_at: number | null;
  handle: string | null;
  reveal_public: number;
  sched_salt: string | null;
  /** Set only on entries restored from a mirror: the schedule commitment, whose dates and salt were not public. */
  sched_fixed: string | null;
  /** Time-lock (hash v4): the ciphertext, its drand round, the SHA-256 the chain covers, and why it failed to open (if it did). */
  tl_round: number | null;
  tl_ct: string | null;
  tl_hash: string | null;
  tl_error: string | null;
  hash_v: number;
  commit_v: number;
  title: string;
  place_mode: PlaceMode;
  place_lat: number | null;
  place_lng: number | null;
  place_label: string | null;
  secret_commit: string | null;
  secret_pkg: string | null;
  secret_blob: string | null;
  likes: number;
  dislikes: number;
  happened: number;
  not_happened: number;
  comment_count: number;
  reports: number;
  listing: number;
  group_id: number | null;
  /** Other listed entries in the same group. Only present on rows read through COLS. */
  similar?: number;
}

/**
 * Nothing is ever removed or hidden because readers flagged it: spam flags only push an
 * entry down the ranking (see HOT). The one exception is the operator, who can take an entry
 * off the lists by hand with the admin tool (listing = 1); it stays reachable by its link
 * and stays in the chain.
 */
const delistedSql = (t: string) => `(${t}listing = 1)`;
const LISTED = `NOT ${delistedSql("")}`;
const isDelisted = (r: Row) => r.listing === 1;
/** Every column, plus how many other listed entries share this one's group. */
const COLS = `e.*, MAX((SELECT COUNT(*) FROM entries g
                         WHERE g.group_id = e.group_id AND NOT ${delistedSql("g.")}) - 1, 0) AS similar`;

export interface PublicEntry {
  seq: number;
  uid: string;
  /** Public headline. Always visible; never redacted. */
  title: string;
  /** The text as sealed. Each redaction is a REDACTION_MARK until the entry is released. */
  text: string;
  /** Number of redactions in the text. */
  redactions: number;
  /** The redacted passages, in order. Present only after release. */
  parts: string[] | null;
  placeMode: PlaceMode;
  /** The place: public from the start, or opened on release. */
  place: Place | null;
  /** True while a place is sealed but not yet released. */
  placeHidden: boolean;
  /** Commitment to the redacted text and hidden place (hash v3). */
  secretCommit: string | null;
  /** The opened payload, present after release. SHA-256 of JSON.stringify([parts, place, salt]) = secretCommit. */
  secret: Secret | null;
  /** The secret, encrypted with a key only the author can derive. Lets the author recover it. */
  secretBlob: string | null;
  createdAt: number;
  mode: Mode;
  /** Scheduled reveal time. Null when the author chose not to show it. */
  revealAt: number | null;
  /** True when the author chose to show the reveal date publicly. */
  revealDatePublic: boolean;
  deadlineAt: number | null;
  status: Status;
  handle: string | null;
  revealedAt: number | null;
  /** Present only after reveal; lets anyone check the author's claim. */
  opening: Opening | null;
  nonce: string;
  commitment: string;
  /** 1 = committed to the author's device key; 2 = per-entry key, content covered (lib/commit.ts). */
  commitV: number;
  entryHash: string;
  prevHash: string;
  hashVersion: number;
  /** Opaque commitment to the schedule (hash v2). The chain covers this, not the dates. */
  schedCommit: string | null;
  /**
   * Set when the author's name and hidden parts are time-locked (hash v4): neither the server nor
   * anyone else can read them until the drand round. `hash` is SHA-256 of the ciphertext, which the
   * chain covers. `round` is shown only when the reveal date is public or the entry is revealed,
   * because the round gives the date away.
   */
  timelock: { hash: string; round: number | null } | null;
  /** The opened schedule, shown only once nothing private is left in it. */
  schedule: { revealAt: number | null; deadlineAt: number | null; salt: string } | null;
  likes: number;
  dislikes: number;
  /** "Did it happen?" tally, open once the entry is revealed. */
  happened: number;
  notHappened: number;
  commentCount: number;
  reports: number;
  /** Taken off the lists as likely spam. Still reachable by its link. */
  delisted: boolean;
  /** How many other entries say much the same thing. */
  similar: number;
}

export { EntryError };

/**
 * Commitment to the schedule. The hash chain covers this value instead of the raw dates,
 * so an author can keep the reveal date private and the chain is still publicly checkable.
 */
function scheduleCommit(
  revealAt: number | null,
  deadlineAt: number | null,
  salt: string,
): string {
  return sha256Hex(JSON.stringify([revealAt, deadlineAt, salt]));
}

function hashEntry(
  prev: string,
  version: number,
  f: {
    seq: number;
    uid: string;
    createdAt: number;
    text: string;
    commitment: string;
    nonce: string;
    mode: Mode;
    revealAt: number | null;
    deadlineAt: number | null;
    schedSalt: string | null;
    /** The schedule commitment itself, when the dates and salt behind it are not held (entries restored from a mirror). */
    schedFixed?: string | null;
    /** SHA-256 of the time-lock ciphertext (hash v4 only). */
    tlHash?: string | null;
    title: string;
    placeMode: PlaceMode;
    placeLat: number | null;
    placeLng: number | null;
    placeLabel: string | null;
    secretCommit: string | null;
  },
): string {
  if (version >= 4) {
    // Version 4 is version 3 plus the hash of the time-lock ciphertext (null if the entry has none).
    return sha256Hex(
      prev +
        "\n" +
        JSON.stringify([
          4,
          f.seq,
          f.uid,
          f.createdAt,
          f.title,
          f.text,
          f.commitment,
          f.nonce,
          f.mode,
          f.schedFixed ?? scheduleCommit(f.revealAt, f.deadlineAt, f.schedSalt ?? ""),
          f.placeMode === "public" ? [f.placeLat, f.placeLng, f.placeLabel ?? ""] : null,
          f.placeMode === "hidden",
          f.secretCommit,
          f.tlHash ?? null,
        ]),
    );
  }
  if (version >= 3) {
    return sha256Hex(
      prev +
        "\n" +
        JSON.stringify([
          3,
          f.seq,
          f.uid,
          f.createdAt,
          f.title,
          f.text,
          f.commitment,
          f.nonce,
          f.mode,
          f.schedFixed ?? scheduleCommit(f.revealAt, f.deadlineAt, f.schedSalt ?? ""),
          f.placeMode === "public" ? [f.placeLat, f.placeLng, f.placeLabel ?? ""] : null,
          f.placeMode === "hidden",
          f.secretCommit,
        ]),
    );
  }
  if (version === 1) {
    // Legacy entries (prototype data) hash the raw dates.
    return sha256Hex(
      prev +
        "\n" +
        JSON.stringify([
          f.seq,
          f.uid,
          f.createdAt,
          f.text,
          f.commitment,
          f.nonce,
          f.mode,
          f.revealAt,
          f.deadlineAt,
        ]),
    );
  }
  return sha256Hex(
    prev +
      "\n" +
      JSON.stringify([
        2,
        f.seq,
        f.uid,
        f.createdAt,
        f.text,
        f.commitment,
        f.nonce,
        f.mode,
        scheduleCommit(f.revealAt, f.deadlineAt, f.schedSalt ?? ""),
      ]),
  );
}

function toPublic(r: Row, now: number): PublicEntry {
  const revealed = r.revealed_at !== null;
  const status: Status = revealed
    ? "revealed"
    : r.deadline_at !== null && r.deadline_at <= now
      ? "unknown"
      : "anonymous";

  const legacy = r.hash_v === 1;
  const datePublic = legacy || r.reveal_public === 1;

  const revealAt = legacy || datePublic || revealed ? r.reveal_at : null;
  const deadlineAt = legacy || status !== "anonymous" ? r.deadline_at : null;

  // Open the schedule only when nothing private remains in it.
  const canOpen =
    !legacy &&
    r.sched_salt !== null &&
    (status !== "anonymous" || (datePublic && r.deadline_at === null));

  // The redacted text and hidden place open only once the entry is released.
  const secret = revealed && r.secret_pkg ? (JSON.parse(r.secret_pkg) as Secret) : null;
  const place: Place | null =
    r.place_mode === "public" && r.place_lat !== null && r.place_lng !== null
      ? { lat: r.place_lat, lng: r.place_lng, label: r.place_label ?? "" }
      : (secret?.place ?? null);

  return {
    seq: r.seq,
    uid: r.uid,
    title: r.title,
    text: r.text,
    redactions: countRedactions(r.text),
    parts: secret?.parts ?? null,
    placeMode: r.place_mode,
    place,
    placeHidden: r.place_mode === "hidden" && place === null,
    secretCommit: r.secret_commit,
    secret,
    secretBlob: r.secret_blob,
    createdAt: r.created_at,
    mode: r.mode,
    revealAt,
    revealDatePublic: datePublic,
    deadlineAt,
    status,
    handle: revealed ? r.handle : null,
    revealedAt: r.revealed_at,
    opening: revealed && r.reveal_pkg ? (JSON.parse(r.reveal_pkg) as Opening) : null,
    nonce: r.nonce,
    commitment: r.commitment,
    commitV: Number(r.commit_v ?? 1),
    entryHash: r.entry_hash,
    prevHash: r.prev_hash,
    hashVersion: r.hash_v,
    schedCommit: legacy ? null : (r.sched_fixed ?? scheduleCommit(r.reveal_at, r.deadline_at, r.sched_salt ?? "")),
    timelock: r.tl_hash ? { hash: r.tl_hash, round: datePublic || revealed ? r.tl_round : null } : null,
    schedule: canOpen
      ? { revealAt: r.reveal_at, deadlineAt: r.deadline_at, salt: r.sched_salt! }
      : null,
    likes: Number(r.likes ?? 0),
    dislikes: Number(r.dislikes ?? 0),
    happened: Number(r.happened ?? 0),
    notHappened: Number(r.not_happened ?? 0),
    commentCount: Number(r.comment_count ?? 0),
    reports: Number(r.reports ?? 0),
    delisted: isDelisted(r),
    similar: Number(r.similar ?? 0),
  };
}

/**
 * Scheduled ("date") and locked reveals are applied lazily whenever entries are read.
 * Entries from older pages hold their opening in plaintext until the date (released by the
 * UPDATE below). Entries sealed with a time-lock (hash v4) hold only ciphertext: those are
 * opened by releaseDueTimelocks(), started in the background at the end of this function.
 */
function applyDueReveals(now: number): void {
  releasePending(now);
  const db = getDb();
  // Read first: most requests find nothing due, and a write would take SQLite's single write
  // lock on every page view.
  const due = db
    .prepare(
      `SELECT 1 FROM entries
        WHERE revealed_at IS NULL AND reveal_pkg IS NOT NULL
          AND reveal_at IS NOT NULL AND reveal_at <= ? LIMIT 1`,
    )
    .get(now);
  if (due)
    db
    .prepare(
      `UPDATE entries
        SET revealed_at = reveal_at,
            handle = json_extract(reveal_pkg, '$.handle')
      WHERE revealed_at IS NULL
        AND reveal_pkg IS NOT NULL
        AND reveal_at IS NOT NULL
        AND reveal_at <= ?`,
    )
    .run(now);
  kickTimelockRelease(now);
}

// ---- Time-locked reveals -------------------------------------------------------------------
// Entries sealed with a time-lock (hash v4) hold no readable opening: the author's browser
// encrypted it to a drand round. When the round has been published, this fetches the beacon
// (verified against the pinned key), decrypts, and re-checks the opening against the entry's
// own commitment exactly as a manual reveal would. A ciphertext that does not hold a valid
// opening is marked failed and never reveals: it can only hurt the entry that carried it.

let releasing = false;
let releaseRetryAt = 0;

/** Starts a release pass in the background if one is due and none is running. Never throws. */
function kickTimelockRelease(now: number): void {
  if (releasing || now < releaseRetryAt) return;
  const due = getDb()
    .prepare(
      `SELECT 1 FROM entries
        WHERE revealed_at IS NULL AND tl_ct IS NOT NULL AND tl_error IS NULL
          AND reveal_at IS NOT NULL AND reveal_at <= ? LIMIT 1`,
    )
    .get(now);
  if (!due) return;
  releasing = true;
  releaseDueTimelocks()
    .then((stillWaiting) => {
      if (stillWaiting > 0) releaseRetryAt = Date.now() + 15_000; // beacon not reachable yet: try again shortly
    })
    .catch((e) => {
      console.error("time-lock release failed:", e instanceof Error ? e.message : e);
      releaseRetryAt = Date.now() + 15_000;
    })
    .finally(() => {
      releasing = false;
    });
}

function markTimelockFailed(uid: string, why: string): void {
  getDb().prepare("UPDATE entries SET tl_error = ? WHERE uid = ? AND revealed_at IS NULL").run(why, uid);
}

/**
 * Opens every time-locked entry whose round has been published. Returns how many due entries
 * could not be opened yet because the beacon was not reachable (they are tried again later).
 */
export async function releaseDueTimelocks(): Promise<number> {
  const db = getDb();
  const now = Date.now();
  const rows = db
    .prepare(
      `SELECT * FROM entries
        WHERE revealed_at IS NULL AND tl_ct IS NOT NULL AND tl_error IS NULL
          AND reveal_at IS NOT NULL AND reveal_at <= ? ORDER BY reveal_at LIMIT 25`,
    )
    .all(now) as unknown as Row[];
  let waiting = 0;
  for (const r of rows) {
    if (r.tl_round === null || r.tl_ct === null || timeOfRound(r.tl_round) > now) continue; // not published yet
    const sig = await getBeacon(r.tl_round);
    if (!sig) { waiting++; continue; }
    let plain: Uint8Array;
    try {
      plain = timelockDecrypt(r.tl_ct, sig);
    } catch {
      markTimelockFailed(r.uid, "the time-locked data could not be opened");
      continue;
    }
    let opening: Opening | null = null;
    let secretPkg: string | null = null;
    try {
      const bundle = decodeBundle(plain);
      opening = parseOpening(bundle.opening);
      if (!opening) throw new Error("no valid opening");
      const content: CommitContent = {
        uid: r.uid,
        title: r.title,
        text: r.text,
        placeMode: r.place_mode,
        place:
          r.place_mode === "public" && r.place_lat !== null && r.place_lng !== null
            ? { lat: r.place_lat, lng: r.place_lng, label: r.place_label ?? "" }
            : null,
        secretCommit: r.secret_commit,
        mode: r.mode,
      };
      if (!(await verifyOpening(r.uid, r.commitment, opening, Number(r.commit_v ?? 1), content))) throw new Error("opening does not match");
      if (r.secret_commit) {
        const s = parseSecret(bundle.secret, countRedactions(r.text), r.place_mode === "hidden");
        if (!s || secretCommitOf(s) !== r.secret_commit) throw new Error("hidden parts do not match");
        secretPkg = JSON.stringify(s);
      }
    } catch {
      markTimelockFailed(r.uid, "the time-locked data did not hold a valid opening");
      continue;
    }
    db.prepare(
      `UPDATE entries SET revealed_at = reveal_at, handle = ?, reveal_pkg = ?, secret_pkg = ?
        WHERE uid = ? AND revealed_at IS NULL`,
    ).run(opening.handle, JSON.stringify(opening), secretPkg, r.uid);
  }
  return waiting;
}

export const MAX_TITLE = 100;

/**
 * The group a new entry belongs to: the group of the most alike earlier entry, if they share
 * at least half their distinctive words; otherwise a new group of its own. The word index
 * narrows the search to a handful of candidates, so this stays quick as the record grows.
 */
function findGroup(seq: number, whole: string): number {
  const words = wordSet(whole);
  if (words.size < SIMILAR_MIN_WORDS) return seq;
  // Longer words are rarer, so they make the best search terms. Quoted: plain words only.
  const terms = [...words].sort((a, b) => b.length - a.length).slice(0, 12);
  const db = getDb();
  const hits = db
    .prepare("SELECT rowid FROM entries_fts WHERE entries_fts MATCH ? AND rowid != ? ORDER BY rank LIMIT 25")
    .all(terms.map((t) => `"${t}"`).join(" OR "), seq) as { rowid: number }[];
  let best = { score: 0, group: seq };
  const get = db.prepare("SELECT title, text, group_id FROM entries WHERE seq = ?");
  for (const h of hits) {
    const c = get.get(h.rowid) as { title: string; text: string; group_id: number | null } | undefined;
    if (!c) continue;
    const other = wordSet(`${c.title}\n${c.text}`);
    if (other.size < SIMILAR_MIN_WORDS) continue;
    const score = jaccard(words, other);
    if (score > best.score) best = { score, group: c.group_id ?? h.rowid };
  }
  return best.score >= SIMILAR_AT ? best.group : seq;
}

export interface SealInput {
  uid: unknown;
  title?: unknown;
  /** "none" | "public" | "hidden". */
  placeMode?: unknown;
  /** The place, only when placeMode is "public". A hidden place travels inside `secret`. */
  place?: unknown;
  secretCommit?: unknown;
  /** Plaintext secret. Required for date and locked entries (the server holds it until release). */
  secret?: unknown;
  secretBlob?: unknown;
  text: unknown;
  commitment: unknown;
  nonce: unknown;
  mode: unknown;
  revealAt: unknown;
  deadlineAt: unknown;
  opening: unknown;
  /**
   * For dated and locked entries: { round, ct }, the opening and hidden parts encrypted in the
   * browser to that drand round (lib/timelock.ts). Replaces `opening` and `secret`, which are then
   * not sent at all, so the server never holds them.
   */
  timelock?: unknown;
  revealPublic?: unknown;
  /** Must be 2: the commitment covers the entry's content (lib/commit.ts). */
  commitV?: unknown;
  /** "hours": hold the post and write it into the record at a random time in the next few hours. */
  delay?: unknown;
}

/** Longest time-lock ciphertext accepted (armored text): a 32 KB bundle is about 44 KB. */
const MAX_TL_CT = 60_000;
/**
 * Longest ciphertext published in the public log (about a 10 KB bundle, far more than a name and a few
 * hidden passages need). Mirrors page through the whole log, so one row must not be able to make a page huge.
 * A longer lock is still covered by the chain through its hash; only the server holds the bytes.
 */
const MAX_PUBLIC_TL_CT = 14_000;

/** Checks the shape of a time-lock and that it is locked to the round the reveal date maps to. */
function parseTimelock(raw: unknown, revealAt: number): { round: number; ct: string; hash: string } {
  const bad = () => new EntryError("The time-lock is not valid. Reload the page and try again.");
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw bad();
  const { round, ct } = raw as Record<string, unknown>;
  if (typeof ct !== "string" || ct.length > MAX_TL_CT || typeof round !== "number") throw bad();
  let locked: number;
  try {
    locked = lockedRound(ct); // strict parse: pinned chain, one stanza, exact shape
  } catch {
    throw bad();
  }
  if (locked !== round) throw bad();
  if (round !== roundForTime(revealAt)) throw new EntryError("The lock on your name doesn't match the reveal date. Reload the page and try again.");
  return { round, ct, hash: sha256Hex(ct) };
}

export async function sealEntry(input: SealInput): Promise<PublicEntry | PendingSeal> {
  assertRecordWritable();
  const { uid, commitment, nonce, mode } = input;
  if (typeof uid !== "string" || !UUID.test(uid)) throw new EntryError("Bad id");
  if (typeof commitment !== "string" || !HEX64.test(commitment))
    throw new EntryError("Bad commitment");
  if (typeof nonce !== "string" || !HEX32.test(nonce)) throw new EntryError("Bad nonce");
  if (mode !== "manual" && mode !== "date" && mode !== "locked")
    throw new EntryError("Bad mode");
  if (input.commitV !== 2)
    throw new EntryError("This page is out of date. Reload it and try again.", 409);

  if (typeof input.text !== "string") throw new EntryError("Text required");
  const text = normText(input.text);
  if (text.length === 0) throw new EntryError("Write something first");
  if (hasHiddenControls(text))
    throw new EntryError("That text contains hidden control characters. Remove them and try again.");
  if (text.length > MAX_TEXT) throw new EntryError(`Too long (max ${MAX_TEXT} characters)`);

  if (typeof input.title !== "string") throw new EntryError("Add a title");
  const title = normTitle(input.title);
  if (title.length === 0) throw new EntryError("Add a title");
  if (hasHiddenControls(title))
    throw new EntryError("The title contains hidden control characters. Remove them and try again.");
  if (title.length > MAX_TITLE) throw new EntryError(`Title too long (max ${MAX_TITLE} characters)`);

  // Door rules: a refused entry is never recorded.
  const whole = `${title}\n${text}`;
  if (countLinks(whole) > MAX_LINKS_ENTRY)
    throw new EntryError(`An entry can include up to ${MAX_LINKS_ENTRY} links`);
  if (blockedDomainIn(whole)) throw new EntryError("That entry links to a blocked site");
  const dup = dupHash(whole);
  if (
    whole.length >= 25 &&
    getDb()
      .prepare("SELECT 1 FROM entries WHERE dup_hash = ? AND created_at > ? LIMIT 1")
      .get(dup, Date.now() - 86_400_000)
  )
    throw new EntryError("An identical entry was sealed in the last day", 409);

  // Redactions and place.
  const redactions = countRedactions(text);
  const placeMode: PlaceMode =
    input.placeMode === "public" || input.placeMode === "hidden" ? input.placeMode : "none";
  let publicPlace: Place | null = null;
  if (placeMode === "public") {
    publicPlace = parsePlace(input.place);
    if (!publicPlace) throw new EntryError("That place is not valid");
  }
  const hasSecret = redactions > 0 || placeMode === "hidden";
  let secretCommit: string | null = null;
  let secretBlob: string | null = null;
  if (hasSecret) {
    if (typeof input.secretCommit !== "string" || !HEX64.test(input.secretCommit))
      throw new EntryError("Missing commitment for the hidden parts");
    secretCommit = input.secretCommit;
    if (
      typeof input.secretBlob !== "string" ||
      input.secretBlob.length > 40_000 ||
      !/^[A-Za-z0-9_-]+$/.test(input.secretBlob)
    )
      throw new EntryError("Missing backup of the hidden parts");
    secretBlob = input.secretBlob;
  } else if (input.secretCommit != null || input.secret != null || input.secretBlob != null) {
    throw new EntryError("Something went wrong with the hidden words. Reload the page and try again.");
  }

  const now = Date.now();
  let revealAt: number | null = null;
  let deadlineAt: number | null = null;
  let pkg: Opening | null = null;
  let secretPkg: Secret | null = null;
  let tl: { round: number; ct: string; hash: string } | null = null;
  if (input.timelock != null && mode === "manual") throw new EntryError("Only dated and locked entries are time-locked");
  // The reveal date is private unless the author explicitly chooses to show it.
  const revealPublic = mode !== "manual" && input.revealPublic === true ? 1 : 0;

  if (mode !== "manual") {
    if (typeof input.revealAt !== "number" || !Number.isFinite(input.revealAt))
      throw new EntryError("Reveal date required");
    revealAt = Math.floor(input.revealAt);
    if (revealAt < now + 30_000) throw new EntryError("Reveal time must be in the future");
    if (input.timelock != null) {
      // Time-locked: the name and hidden parts arrive only as ciphertext. The server cannot check what
      // is inside until the round, so a ciphertext that turns out empty simply never reveals.
      if (input.opening != null || input.secret != null)
        throw new EntryError("A time-locked entry must not also send its name or hidden parts");
      tl = parseTimelock(input.timelock, revealAt);
    } else {
      pkg = parseOpening(input.opening);
      if (!pkg) throw new EntryError("Add a name to reveal on that date");
      const content: CommitContent = {
        uid,
        title,
        text,
        placeMode,
        place: publicPlace,
        secretCommit,
        mode,
      };
      if (!(await verifyOpening(uid, commitment, pkg, 2, content)))
        throw new EntryError("We couldn't confirm that this post belongs to your key. Reload the page and try again.");
      if (hasSecret) {
        // Older pages: the server holds the payload until the date. New pages time-lock it instead.
        secretPkg = parseSecret(input.secret, redactions, placeMode === "hidden");
        if (!secretPkg || secretCommitOf(secretPkg) !== secretCommit)
          throw new EntryError("The hidden parts did not match their commitment");
      }
    }
  }

  if (input.deadlineAt !== null && input.deadlineAt !== undefined) {
    if (typeof input.deadlineAt !== "number" || !Number.isFinite(input.deadlineAt))
      throw new EntryError("Bad deadline");
    deadlineAt = Math.floor(input.deadlineAt);
    if (deadlineAt < now + 30_000) throw new EntryError("Deadline must be in the future");
  }

  const prepared: Prepared = {
    uid, text, commitment, nonce, mode, revealAt, deadlineAt, title, placeMode, publicPlace,
    secretCommit, tl, pkg, revealPublic, secretPkg, secretBlob, whole, dup,
  };
  if (input.delay === "hours") return queuePending(prepared, now);
  return insertPrepared(prepared, now);
}

/** Everything a checked entry needs to be written into the chain, at sealing or later at its release. */
interface Prepared {
  uid: string;
  text: string;
  commitment: string;
  nonce: string;
  mode: Mode;
  revealAt: number | null;
  deadlineAt: number | null;
  title: string;
  placeMode: PlaceMode;
  publicPlace: Place | null;
  secretCommit: string | null;
  tl: { round: number; ct: string; hash: string } | null;
  pkg: Opening | null;
  revealPublic: number;
  secretPkg: Secret | null;
  secretBlob: string | null;
  whole: string;
  dup: string;
}

// ---- Delayed release ---------------------------------------------------------------------
// A post that appears seconds after its author was online can be matched to them by anyone who watches the
// network. So by default a sealed post waits, and is written into the record at a random time in the next
// few hours. Its recorded time is the time it was released. Nothing about it is public until then.

const HOUR = 3_600_000;
export const DELAY_MIN = HOUR;
export const DELAY_MAX = 6 * HOUR;

export interface PendingSeal {
  pending: true;
  uid: string;
  /** The post appears somewhere between these two times. */
  releaseFrom: number;
  releaseBy: number;
}

function randomBelow(n: number): number {
  return Number(randomBytes(6).readUIntBE(0, 6) % n);
}

function queuePending(p: Prepared, now: number): PendingSeal {
  const latest = now + DELAY_MAX;
  if ((p.revealAt !== null && p.revealAt < latest + 60_000) || (p.deadlineAt !== null && p.deadlineAt < latest + 60_000))
    throw new EntryError(
      "A delayed post appears some time in the next 6 hours, so its reveal date and deadline have to be later than that. Pick a later date, or publish it now.",
    );
  const db = getDb();
  if (db.prepare("SELECT 1 FROM entries WHERE uid = ? OR commitment = ? OR nonce = ?").get(p.uid, p.commitment, p.nonce))
    throw new EntryError("That entry already exists", 409);
  const releaseAt = now + DELAY_MIN + randomBelow(DELAY_MAX - DELAY_MIN);
  try {
    db.prepare(
      "INSERT INTO pending_entries (uid, commitment, nonce, payload, release_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(p.uid, p.commitment, p.nonce, JSON.stringify(p), releaseAt, now);
  } catch (e) {
    if (e instanceof Error && /UNIQUE/i.test(e.message)) throw new EntryError("That entry already exists", 409);
    throw e;
  }
  return { pending: true, uid: p.uid, releaseFrom: now + DELAY_MIN, releaseBy: latest };
}

let releasingPending = false;
/** Writes every waiting post whose time has come into the record. Cheap when nothing is due. */
export function releasePending(now: number): number {
  if (releasingPending) return 0;
  const db = getDb();
  if (!db.prepare("SELECT 1 FROM pending_entries WHERE release_at <= ? LIMIT 1").get(now)) return 0;
  releasingPending = true;
  let done = 0;
  try {
    assertRecordWritable();
    const rows = db
      .prepare("SELECT uid, payload FROM pending_entries WHERE release_at <= ? ORDER BY release_at LIMIT 50")
      .all(now) as { uid: string; payload: string }[];
    for (const r of rows) {
      try {
        insertPrepared(JSON.parse(r.payload) as Prepared, now);
        done++;
      } catch (e) {
        // A duplicate can never be written; anything else is tried again next time.
        if (!(e instanceof EntryError && e.status === 409)) continue;
      }
      db.prepare("DELETE FROM pending_entries WHERE uid = ?").run(r.uid);
    }
  } catch {
    /* the record is not writable here now: the posts keep waiting */
  } finally {
    releasingPending = false;
  }
  return done;
}

/** Whether a post is still waiting to be released (it is otherwise unknown here). */
export function isPending(uid: string): boolean {
  return !!getDb().prepare("SELECT 1 FROM pending_entries WHERE uid = ?").get(uid);
}

function insertPrepared(p: Prepared, now: number): PublicEntry {
  const {
    uid, text, commitment, nonce, mode, revealAt, deadlineAt, title, placeMode, publicPlace,
    secretCommit, tl, pkg, revealPublic, secretPkg, secretBlob, whole, dup,
  } = p;
  const schedSalt = randomBytes(16).toString("hex");
  const db = getDb();
  db.exec("BEGIN IMMEDIATE");
  try {
    const last = db
      .prepare("SELECT seq, entry_hash, created_at FROM entries ORDER BY seq DESC LIMIT 1")
      .get() as { seq: number; entry_hash: string; created_at: number } | undefined;
    const seq = (last?.seq ?? 0) + 1;
    const prev = last?.entry_hash ?? GENESIS;
    // Never let the recorded time run backwards, even if the system clock does.
    const createdAt = Math.max(now, last?.created_at ?? 0);
    const hashV = tl ? 4 : 3;
    const entryHash = hashEntry(prev, hashV, {
      seq,
      uid,
      createdAt,
      text,
      commitment,
      nonce,
      mode,
      revealAt,
      deadlineAt,
      schedSalt,
      title,
      placeMode,
      placeLat: publicPlace?.lat ?? null,
      placeLng: publicPlace?.lng ?? null,
      placeLabel: publicPlace?.label ?? null,
      secretCommit,
      tlHash: tl?.hash ?? null,
    });
    db.prepare(
      `INSERT INTO entries
         (seq, uid, text, commitment, nonce, created_at, mode, reveal_at, deadline_at,
          prev_hash, entry_hash, reveal_pkg, reveal_public, sched_salt, hash_v, commit_v,
          title, place_mode, place_lat, place_lng, place_label,
          secret_commit, secret_pkg, secret_blob, tl_round, tl_ct, tl_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      seq,
      uid,
      text,
      commitment,
      nonce,
      createdAt,
      mode,
      revealAt,
      deadlineAt,
      prev,
      entryHash,
      pkg ? JSON.stringify(pkg) : null,
      revealPublic,
      schedSalt,
      hashV,
      title,
      placeMode,
      publicPlace?.lat ?? null,
      publicPlace?.lng ?? null,
      publicPlace?.label ?? null,
      secretCommit,
      secretPkg ? JSON.stringify(secretPkg) : null,
      secretBlob,
      tl?.round ?? null,
      tl?.ct ?? null,
      tl?.hash ?? null,
    );
    db.prepare("INSERT INTO entries_fts (rowid, body) VALUES (?, ?)").run(seq, whole);
    db.prepare("UPDATE entries SET dup_hash = ?, group_id = ? WHERE seq = ?").run(
      dup,
      findGroup(seq, whole),
      seq,
    );
    db.exec("COMMIT");
  } catch (e) {
    db.exec("ROLLBACK");
    if (e instanceof Error && /UNIQUE/i.test(e.message))
      throw new EntryError("That entry already exists", 409);
    throw e;
  }
  return getEntry(uid)!;
}


export function getEntry(uid: string): PublicEntry | null {
  const now = Date.now();
  applyDueReveals(now);
  const r = getDb().prepare(`SELECT ${COLS} FROM entries e WHERE uid = ?`).get(uid) as
    | Row
    | undefined;
  return r ? toPublic(r, now) : null;
}

function statusClause(
  status: Status | undefined,
  now: number,
): { sql: string; params: number[] } | null {
  if (status === "revealed") return { sql: "revealed_at IS NOT NULL", params: [] };
  if (status === "anonymous")
    return {
      sql: "revealed_at IS NULL AND (deadline_at IS NULL OR deadline_at > ?)",
      params: [now],
    };
  if (status === "unknown")
    return {
      sql: "revealed_at IS NULL AND deadline_at IS NOT NULL AND deadline_at <= ?",
      params: [now],
    };
  return null;
}

/** Escape LIKE wildcards so a search for "100%" matches literally. */
function likePattern(q: string): string {
  return "%" + q.replace(/[\\%_]/g, (c) => "\\" + c) + "%";
}

/** Text and sealed-date filters shared by the list and the counts. Days are YYYY-MM-DD, in UTC. */
export type Filter = { q?: string; from?: string; to?: string };

const DAY = /^\d{4}-\d{2}-\d{2}$/;

/** Start of a UTC day in ms, or null if the text is not a real date. */
function dayStart(s: string | undefined): number | null {
  if (!s || !DAY.test(s)) return null;
  const ms = Date.parse(s + "T00:00:00Z");
  return Number.isNaN(ms) || new Date(ms).toISOString().slice(0, 10) !== s ? null : ms;
}

function filterClauses(f: Filter, where: string[], params: (string | number)[]) {
  const q = f.q?.trim().slice(0, 100);
  if (q) {
    where.push("(text LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\')");
    params.push(likePattern(q), likePattern(q));
  }
  const from = dayStart(f.from);
  if (from !== null) {
    where.push("created_at >= ?");
    params.push(from);
  }
  const to = dayStart(f.to);
  if (to !== null) {
    where.push("created_at < ?");
    params.push(to + 86_400_000);
  }
}

export type Sort = "new" | "top";

/**
 * "top" ranks by net likes less a spam penalty, weighted toward recent entries so the front
 * page keeps moving:
 *   (likes - dislikes - (2 ^ spam flags - 1)) / (hours since sealed + 2) ^ 1.5
 * The penalty doubles with every flag: 1 flag costs one like, 2 cost 3, 3 cost 7, 5 cost 31,
 * 10 cost 1,023. Liked entries rise, disliked or flagged ones sink below everything with no
 * votes, and all drift back toward the middle as they age. Ties go to the newest.
 */
const HOT = `(likes - dislikes - (pow(2, MIN(reports, ${SPAM_CAP})) - 1)) / pow((? - created_at) / 3600000.0 + 2, 1.5)`;

export function listEntries(opts: {
  status?: Status;
  sort?: Sort;
  /** Used by "top", which can't page by sequence number. */
  offset?: number;
  limit?: number;
  beforeSeq?: number;
  q?: string;
  from?: string;
  to?: string;
}): PublicEntry[] {
  const now = Date.now();
  applyDueReveals(now);
  const where: string[] = [];
  const params: (string | number)[] = [];
  const sc = statusClause(opts.status, now);
  if (sc) {
    where.push(sc.sql);
    params.push(...sc.params);
  }
  filterClauses(opts, where, params);
  where.push(LISTED);
  const top = opts.sort === "top";
  if (opts.beforeSeq && !top) {
    where.push("seq < ?");
    params.push(opts.beforeSeq);
  }
  const limit = Math.min(Math.max(opts.limit ?? 50, 1), 100);
  const offset = top ? Math.min(Math.max(Math.floor(opts.offset ?? 0), 0), 10_000) : 0;
  const cond = " WHERE " + where.join(" AND ");
  // "top" shows one entry per group of similar entries: the best ranked of them. The rest
  // are a tap away through its "similar" link. "new" is the full record, nothing folded.
  const sql = top
    ? `SELECT * FROM (
         SELECT *, ROW_NUMBER() OVER (PARTITION BY group_id ORDER BY hot DESC, seq DESC) AS rn
           FROM (SELECT ${COLS}, ${HOT} AS hot FROM entries e${cond})
       ) WHERE rn = 1 ORDER BY hot DESC, seq DESC LIMIT ? OFFSET ?`
    : `SELECT ${COLS} FROM entries e${cond} ORDER BY seq DESC LIMIT ?`;
  const rows = getDb()
    .prepare(sql)
    // HOT's "now" comes first: it sits in the column list, ahead of the WHERE.
    .all(...(top ? [now, ...params, limit, offset] : [...params, limit])) as unknown as Row[];
  return rows.map((r) => toPublic(r, now));
}

/** Entry counts per status, optionally limited to a search and a sealed-date range. */
export function countEntries(f: Filter = {}): Record<"all" | Status, number> {
  const now = Date.now();
  applyDueReveals(now);
  const one = (status?: Status): number => {
    const where: string[] = [];
    const params: (string | number)[] = [];
    const sc = statusClause(status, now);
    if (sc) {
      where.push(sc.sql);
      params.push(...sc.params);
    }
    filterClauses(f, where, params);
    where.push(LISTED);
    const row = getDb()
      .prepare("SELECT COUNT(*) AS n FROM entries WHERE " + where.join(" AND "))
      .get(...params) as { n: number };
    return Number(row.n);
  };
  return {
    all: one(),
    revealed: one("revealed"),
    anonymous: one("anonymous"),
    unknown: one("unknown"),
  };
}

export async function revealEntry(uid: string, rawOpening: unknown): Promise<PublicEntry> {
  const now = Date.now();
  applyDueReveals(now);
  const db = getDb();
  const r = db.prepare("SELECT * FROM entries WHERE uid = ?").get(uid) as Row | undefined;
  if (!r) throw new EntryError("Entry not found", 404);
  if (r.revealed_at !== null) throw new EntryError("Already revealed", 409);
  if (r.mode === "locked")
    throw new EntryError("This entry is locked and will reveal on its date", 403);
  const op = parseOpening(rawOpening);
  if (!op) throw new EntryError("Bad reveal data");
  const content: CommitContent = {
    uid,
    title: r.title,
    text: r.text,
    placeMode: r.place_mode,
    place:
      r.place_mode === "public" && r.place_lat !== null && r.place_lng !== null
        ? { lat: r.place_lat, lng: r.place_lng, label: r.place_label ?? "" }
        : null,
    secretCommit: r.secret_commit,
    mode: r.mode,
  };
  if (!(await verifyOpening(uid, r.commitment, op, Number(r.commit_v ?? 1), content)))
    throw new EntryError("That key didn't create this post, or the post has been changed.", 403);
  // A dated entry already holds the author's signed name from when it was sealed. Revealing
  // early only brings the date forward: the key proves authorship, the sealed name is shown.
  const sealed = r.mode === "date" && r.reveal_pkg ? (JSON.parse(r.reveal_pkg) as Opening) : null;
  const final = sealed ?? op;
  // Releasing the entry also opens its redactions and hidden place.
  let secretPkg: string | null = r.secret_pkg;
  if (r.secret_commit && !secretPkg) {
    const s = parseSecret(
      (rawOpening as Record<string, unknown>).secret,
      countRedactions(r.text),
      r.place_mode === "hidden",
    );
    if (!s || secretCommitOf(s) !== r.secret_commit)
      throw new EntryError("The hidden parts are missing or do not match what was sealed", 400);
    secretPkg = JSON.stringify(s);
  }
  const res = db
    .prepare(
      `UPDATE entries SET revealed_at = ?, handle = ?, reveal_pkg = ?, secret_pkg = ?
        WHERE uid = ? AND revealed_at IS NULL`,
    )
    .run(now, final.handle, JSON.stringify(final), secretPkg, uid);
  if (Number(res.changes) === 0) throw new EntryError("Already revealed", 409);
  return getEntry(uid)!;
}

export type Vote = -1 | 0 | 1;
export type VoteKind = "like" | "outcome";
const VOTER = /^[0-9a-f]{64}$/;

// Fixed table and column names per kind; never built from input.
const VOTE_KINDS = {
  like: { table: "votes", up: "likes", down: "dislikes" },
  outcome: { table: "outcome_votes", up: "happened", down: "not_happened" },
} as const;

/**
 * Records one browser's vote on an entry: like/dislike, or (once revealed) happened/didn't.
 * 1 = up, -1 = down, 0 = clear. Voting again replaces that browser's earlier vote. The token
 * is random and lives only in the browser; the server keeps a hash of it, never an address.
 */
export function voteEntry(
  uid: string,
  token: unknown,
  rawValue: unknown,
  kind: VoteKind = "like",
): { up: number; down: number; mine: Vote } {
  if (!UUID.test(uid)) throw new EntryError("Entry not found", 404);
  if (typeof token !== "string" || !VOTER.test(token)) throw new EntryError("Invalid voter");
  if (rawValue !== -1 && rawValue !== 0 && rawValue !== 1) throw new EntryError("Invalid vote");
  const value = rawValue as Vote;
  const k = VOTE_KINDS[kind];
  const voter = sha256Hex(`whenisaid:voter:v1:${token}`);
  if (kind === "outcome") applyDueReveals(Date.now());
  const db = getDb();
  db.exec("BEGIN IMMEDIATE");
  try {
    const entry = db.prepare("SELECT revealed_at FROM entries WHERE uid = ?").get(uid) as
      | { revealed_at: number | null }
      | undefined;
    if (!entry) throw new EntryError("Entry not found", 404);
    if (kind === "outcome" && entry.revealed_at === null)
      throw new EntryError("You can say whether it happened once it has been revealed", 409);
    const prev = db
      .prepare(`SELECT value FROM ${k.table} WHERE entry_uid = ? AND voter = ?`)
      .get(uid, voter) as { value: number } | undefined;
    const before = (prev?.value ?? 0) as Vote;
    if (before !== value) {
      if (value === 0)
        db.prepare(`DELETE FROM ${k.table} WHERE entry_uid = ? AND voter = ?`).run(uid, voter);
      else
        db.prepare(
          `INSERT INTO ${k.table} (entry_uid, voter, value, at) VALUES (?, ?, ?, ?)
             ON CONFLICT (entry_uid, voter) DO UPDATE SET value = excluded.value, at = excluded.at`,
        ).run(uid, voter, value, Date.now());
      const du = (value === 1 ? 1 : 0) - (before === 1 ? 1 : 0);
      const dd = (value === -1 ? 1 : 0) - (before === -1 ? 1 : 0);
      db.prepare(
        `UPDATE entries SET ${k.up} = ${k.up} + ?, ${k.down} = ${k.down} + ? WHERE uid = ?`,
      ).run(du, dd, uid);
    }
    const c = db.prepare(`SELECT ${k.up} AS up, ${k.down} AS down FROM entries WHERE uid = ?`).get(
      uid,
    ) as { up: number; down: number };
    db.exec("COMMIT");
    return { up: Number(c.up), down: Number(c.down), mine: value };
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
}

/**
 * "Called it": revealed entries people have voted on, most agreed-that-it-happened first.
 * Net (happened - didn't), then the most "happened" votes, then newest. Paged by offset.
 */
export function listCalled(opts: { offset?: number; limit?: number } = {}): PublicEntry[] {
  const now = Date.now();
  applyDueReveals(now);
  const limit = Math.min(Math.max(opts.limit ?? 25, 1), 100);
  const offset = Math.min(Math.max(Math.floor(opts.offset ?? 0), 0), 10_000);
  const rows = getDb()
    .prepare(
      `SELECT ${COLS} FROM entries e
        WHERE revealed_at IS NOT NULL AND happened + not_happened > 0 AND ${LISTED}
        ORDER BY happened - not_happened DESC, happened DESC, seq DESC
        LIMIT ? OFFSET ?`,
    )
    .all(limit, offset) as unknown as Row[];
  return rows.map((r) => toPublic(r, now));
}

/** Other entries that say much the same thing, best ranked first. Paged by offset. */
export function listSimilar(uid: string, opts: { offset?: number; limit?: number } = {}): PublicEntry[] {
  if (!UUID.test(uid)) return [];
  const now = Date.now();
  applyDueReveals(now);
  const limit = Math.min(Math.max(opts.limit ?? 25, 1), 100);
  const offset = Math.min(Math.max(Math.floor(opts.offset ?? 0), 0), 10_000);
  const rows = getDb()
    .prepare(
      `SELECT ${COLS}, ${HOT} AS hot FROM entries e
        WHERE group_id = (SELECT group_id FROM entries WHERE uid = ?) AND uid != ? AND ${LISTED}
        ORDER BY hot DESC, seq DESC LIMIT ? OFFSET ?`,
    )
    .all(now, uid, uid, limit, offset) as unknown as Row[];
  return rows.map((r) => toPublic(r, now));
}

/** One spam flag per browser per entry. Flags lower its ranking; they never hide or remove it. */
export function reportEntry(uid: string, token: unknown): { reports: number } {
  if (!UUID.test(uid)) throw new EntryError("Entry not found", 404);
  if (typeof token !== "string" || !VOTER.test(token)) throw new EntryError("Invalid voter");
  const voter = sha256Hex(`whenisaid:voter:v1:${token}`);
  const db = getDb();
  db.exec("BEGIN IMMEDIATE");
  try {
    if (!db.prepare("SELECT 1 FROM entries WHERE uid = ?").get(uid))
      throw new EntryError("Entry not found", 404);
    const res = db
      .prepare("INSERT OR IGNORE INTO entry_reports (entry_uid, voter, at) VALUES (?, ?, ?)")
      .run(uid, voter, Date.now());
    if (Number(res.changes) > 0)
      db.prepare("UPDATE entries SET reports = reports + 1 WHERE uid = ?").run(uid);
    const r = db.prepare("SELECT * FROM entries WHERE uid = ?").get(uid) as unknown as Row;
    db.exec("COMMIT");
    return { reports: Number(r.reports) };
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
}

/** Recomputes the whole hash chain. Used by /api/chain and the smoke test. */
export function verifyChain(): { ok: boolean; count: number; tip: string; brokenAt?: number } {
  const rows = getDb()
    .prepare("SELECT * FROM entries ORDER BY seq ASC")
    .all() as unknown as Row[];
  let prev = GENESIS;
  for (const r of rows) {
    const h = hashEntry(prev, r.hash_v, {
      seq: r.seq,
      uid: r.uid,
      createdAt: r.created_at,
      text: r.text,
      commitment: r.commitment,
      nonce: r.nonce,
      mode: r.mode,
      revealAt: r.reveal_at,
      deadlineAt: r.deadline_at,
      schedSalt: r.sched_salt,
      schedFixed: r.sched_fixed,
      tlHash: r.tl_hash,
      title: r.title,
      placeMode: r.place_mode,
      placeLat: r.place_lat,
      placeLng: r.place_lng,
      placeLabel: r.place_label,
      secretCommit: r.secret_commit,
    });
    if (r.prev_hash !== prev || r.entry_hash !== h)
      return { ok: false, count: rows.length, tip: prev, brokenAt: r.seq };
    prev = h;
  }
  return { ok: true, count: rows.length, tip: prev };
}

/**
 * The record in the form anyone can re-check the chain from: exactly the fields the hash covers,
 * and nothing private. Served by /api/log; scripts/verify-log.mjs recomputes the chain from it.
 */
export function listLog(afterSeq: number, limit: number) {
  const rows = getDb()
    .prepare("SELECT * FROM entries WHERE seq > ? ORDER BY seq ASC LIMIT ?")
    .all(Math.max(0, Math.floor(afterSeq) || 0), Math.min(Math.max(Math.floor(limit) || 500, 1), 1000)) as unknown as Row[];
  return rows.map((r) => ({
    seq: r.seq,
    uid: r.uid,
    createdAt: r.created_at,
    title: r.title,
    text: r.text,
    commitment: r.commitment,
    commitV: Number(r.commit_v ?? 1),
    nonce: r.nonce,
    mode: r.mode,
    hashV: r.hash_v,
    schedCommit: r.hash_v >= 2 ? (r.sched_fixed ?? scheduleCommit(r.reveal_at, r.deadline_at, r.sched_salt ?? "")) : null,
    placeMode: r.place_mode,
    place:
      r.place_mode === "public" ? { lat: r.place_lat, lng: r.place_lng, label: r.place_label ?? "" } : null,
    secretCommit: r.secret_commit,
    // Hash v4: the chain covers the ciphertext's hash. The ciphertext itself carries its unlock
    // round, so it is published only when the reveal date is public or the entry is revealed.
    ...(r.hash_v >= 4
      ? {
          tlHash: r.tl_hash,
          tl:
            r.tl_ct !== null && r.tl_round !== null && r.tl_ct.length <= MAX_PUBLIC_TL_CT && (r.reveal_public === 1 || r.revealed_at !== null)
              ? { round: r.tl_round, ct: r.tl_ct }
              : null,
        }
      : {}),
    prevHash: r.prev_hash,
    entryHash: r.entry_hash,
  }));
}

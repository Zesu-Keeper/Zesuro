import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { getDb } from "./db";
import { EntryError } from "./errors";
import { sha256Hex } from "./opening";

// Spam rules. Everything here runs on this server: no outside service ever sees a visitor
// or their text. Rules that refuse a post run before anything is recorded, so they never
// touch the permanent record.

export { LINKS_AT, SPAM_CAP } from "./limits";
export const MAX_LINKS_COMMENT = 2;
export const MAX_LINKS_ENTRY = 5;
/** The same comment text may appear on this many entries within DUP_WINDOW; more is refused. */
export const DUP_ENTRIES = 2;
export const DUP_WINDOW_MS = 30 * 86_400_000;

const URL_RE = /https?:\/\/[^\s<>"']+/gi;
const DOMAIN_RE = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}/gi;

export function countLinks(text: string): number {
  return (text.match(URL_RE) ?? []).length;
}

/** Every domain-looking token, with or without "http://", lower-cased, without "www.". */
export function domainsIn(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.normalize("NFKC").toLowerCase().match(DOMAIN_RE) ?? [])
    out.add(m.replace(/^www\./, ""));
  return [...out];
}

/** The blocked domain this text mentions (itself or as a parent domain), or null. */
export function blockedDomainIn(text: string): string | null {
  const domains = domainsIn(text);
  if (domains.length === 0) return null;
  const rows = getDb().prepare("SELECT domain FROM blocked_domains").all() as { domain: string }[];
  if (rows.length === 0) return null;
  const blocked = new Set(rows.map((r) => r.domain));
  for (const d of domains) {
    const parts = d.split(".");
    for (let i = 0; i < parts.length - 1; i++) {
      const suffix = parts.slice(i).join(".");
      if (blocked.has(suffix)) return suffix;
    }
  }
  return null;
}

/** Text reduced to its words, so copies that differ only in case, spacing or punctuation match. */
export function dupHash(text: string): string {
  const norm = text
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim();
  return sha256Hex(`whenisaid:dup:v1:${norm}`);
}

// ---- Form tickets -------------------------------------------------------------------------
// A form fetches a ticket when it opens and returns it with the post. The server checks that
// it issued the ticket and that a human-plausible moment has passed. Stateless: nothing is
// stored about who asked. The key lives in memory and changes when the app restarts.

const g = globalThis as unknown as { __zesuroTicketKey?: Buffer };
const ticketKey = () => g.__zesuroTicketKey ?? (g.__zesuroTicketKey = randomBytes(32));
const sign = (t: string) => createHmac("sha256", ticketKey()).update(t).digest("base64url");
const usedTickets = () =>
  ((globalThis as unknown as { __zesuroUsedTickets?: Map<string, number> }).__zesuroUsedTickets ??= new Map());
const MIN_AGE_MS = 2_000;
const MAX_AGE_MS = 12 * 3_600_000;
// Test switch for the smoke test. Never honoured in production builds.
const testing = () => process.env.RATE_LIMIT_OFF === "1" && process.env.NODE_ENV !== "production";

export function issueTicket(): string {
  const t = String(Date.now());
  return `${t}.${sign(t)}`;
}

/** Throws (status 428) unless `ticket` is one of ours, old enough and not stale. */
export function requireTicket(ticket: unknown, honeypot: unknown): void {
  // The honeypot is a field people never see. Only a script fills it in.
  if (honeypot !== undefined && honeypot !== null && honeypot !== "")
    throw new EntryError("That could not be posted");
  const stale = new EntryError("This form has expired. Please try again.", 428);
  if (typeof ticket !== "string" || ticket.length > 100) throw stale;
  const [t, mac] = ticket.split(".");
  if (!t || !mac || !/^\d{13}$/.test(t)) throw stale;
  const want = Buffer.from(sign(t));
  const got = Buffer.from(mac);
  if (want.length !== got.length || !timingSafeEqual(want, got)) throw stale;
  const age = Date.now() - Number(t);
  if (age > MAX_AGE_MS || age < 0) throw stale;
  if (age < MIN_AGE_MS && !testing()) throw new EntryError("That was too fast. Try again.", 428);
  // A ticket works once. (Kept in memory; a restart also invalidates every ticket.)
  const used = usedTickets();
  if (used.has(mac)) throw stale;
  used.set(mac, Number(t) + MAX_AGE_MS);
  if (used.size > 50_000) {
    const now = Date.now();
    for (const [k, exp] of used) if (exp < now) used.delete(k);
    // Still too many: forget the oldest. Those tickets are old enough to be refused as stale soon.
    for (const k of used.keys()) {
      if (used.size <= 40_000) break;
      used.delete(k);
    }
  }
}

// ---- Similar entries ----------------------------------------------------------------------

const STOP = new Set(
  (
    "the and for are but not you all any can had her was one our out day get has him his how " +
    "its may new now old see two way who did yes this that with have from they will would " +
    "there their what about which when make like time just know take into year your some " +
    "could them than then look only come over think also back after use work first well " +
    "even want because these give most been were said each she more very much such here " +
    "being does doing going where while should those other"
  ).split(" "),
);

/** The distinctive words of a text: lower-case, 3+ letters, common words removed. */
export function wordSet(text: string): Set<string> {
  const out = new Set<string>();
  for (const w of text.normalize("NFKC").toLowerCase().split(/[^\p{L}\p{N}]+/u))
    if (w.length >= 3 && w.length <= 40 && !STOP.has(w)) out.add(w);
  return out;
}

/** Share of words two texts have in common (0 to 1). */
export function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let both = 0;
  for (const w of a) if (b.has(w)) both++;
  return both / (a.size + b.size - both);
}

/** Entries at least this alike are grouped. Texts with fewer distinctive words are never grouped. */
export const SIMILAR_AT = 0.5;
export const SIMILAR_MIN_WORDS = 4;

import fs from "node:fs";
import path from "node:path";
import { EntryError } from "./errors";

/**
 * One server at a time writes the record: the one the root key has delegated to (see
 * scripts/root.mjs). When data/authority.json exists, this server accepts new entries and comments
 * only if its own signing key (data/anchor-key.pub) is the writer named in the latest delegation.
 * A replacement server restored from a snapshot has a new key and so stays read-only until the root
 * key delegates to it. Without an authority file (the way the site started) nothing is restricted.
 *
 * This is a guard against a server that has not been authorised writing by accident. It is not a
 * boundary against someone who controls this machine; that is what mirrors and the root key are for:
 * they refuse a signed tip from a server that is not the rightful writer.
 */
let cache: { at: number; ok: boolean; why: string } | null = null;

export function writerStatus(): { ok: boolean; why: string } {
  if (cache && Date.now() - cache.at < 5_000) return cache;
  const dir = path.join(process.cwd(), "data");
  let result = { ok: true, why: "no authority file: unrestricted" };
  let text: string | null = null;
  try {
    text = fs.readFileSync(path.join(dir, "authority.json"), "utf8");
  } catch {
    text = null;
  }
  if (text !== null) {
    try {
      const auth = JSON.parse(text) as { delegations?: { head?: string }[] };
      const last = auth.delegations?.length ? (JSON.parse(String(auth.delegations[auth.delegations.length - 1].head)) as { writer?: string }) : null;
      let own = "";
      try {
        own = fs.readFileSync(path.join(dir, "anchor-key.pub"), "utf8").trim();
      } catch {
        own = "";
      }
      if (!last?.writer) result = { ok: false, why: "the authority file names no writer" };
      else if (!own) result = { ok: false, why: "this server has no signing key yet" };
      else if (own !== last.writer) result = { ok: false, why: "this server is not the writer the root key delegated to" };
      else result = { ok: true, why: "this server is the delegated writer" };
    } catch {
      result = { ok: false, why: "the authority file cannot be read" };
    }
  }
  cache = { at: Date.now(), ...result };
  return result;
}

/** Throws (HTTP 503) unless this server may write the record. Call before adding an entry or comment. */
export function assertRecordWritable(): void {
  const s = writerStatus();
  if (!s.ok) throw new EntryError("This server is read-only: it has not been authorised to write the record. Try the current address.", 503);
}

/** For tests: forget the cached answer. */
export function resetWriterCache(): void {
  cache = null;
}

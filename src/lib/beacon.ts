/**
 * Fetching drand beacon signatures on the server, to open time-locked reveals when their round comes.
 *
 * A relay is never trusted: every signature is checked against the pinned quicknet public key
 * (timelock.ts) before it is used or stored, so a lying or compromised relay can only fail to
 * answer. Verified signatures are kept in the `beacons` table, one fetch per round.
 *
 * Only the server's own address talks to the relays. Visitors' browsers never do, so drand's hosts
 * learn nothing about who uses Zesuro.
 */
import { getDb } from "./db";
import { QUICKNET, timeOfRound, verifyBeacon } from "./timelock";

/** Public relays for the quicknet chain. Override with ZESURO_DRAND_URLS (comma separated). */
const DEFAULT_RELAYS = ["https://api.drand.sh", "https://api2.drand.sh", "https://api3.drand.sh", "https://drand.cloudflare.com"];
const TIMEOUT_MS = 8000;

function relays(): string[] {
  const custom = (process.env.ZESURO_DRAND_URLS ?? "").split(",").map((s) => s.trim().replace(/\/+$/, "")).filter((s) => /^https:\/\//.test(s));
  return custom.length ? custom : DEFAULT_RELAYS;
}

/** The verified signature (hex) for a round that has been published, or null if none could be had. */
export async function getBeacon(round: number): Promise<string | null> {
  if (!Number.isSafeInteger(round) || round < 1 || timeOfRound(round) > Date.now()) return null;
  const db = getDb();
  const have = db.prepare("SELECT sig FROM beacons WHERE round = ?").get(round) as { sig: string } | undefined;
  if (have && verifyBeacon(round, have.sig)) return have.sig;
  for (const base of relays()) {
    try {
      const res = await fetch(`${base}/${QUICKNET.chainHash}/public/${round}`, { signal: AbortSignal.timeout(TIMEOUT_MS), headers: { accept: "application/json" } });
      if (!res.ok) continue;
      const j = (await res.json()) as { round?: unknown; signature?: unknown };
      if (j.round !== round || typeof j.signature !== "string" || !verifyBeacon(round, j.signature)) continue;
      db.prepare("INSERT OR REPLACE INTO beacons (round, sig, at) VALUES (?, ?, ?)").run(round, j.signature, Date.now());
      return j.signature;
    } catch {
      /* this relay is down or slow: try the next */
    }
  }
  return null;
}

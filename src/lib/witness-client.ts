// Browser only. A drand beacon fetched just before posting, to put in the post as a time witness (hash v6).
// The beacon's signature is checked here against the pinned drand key, so the site can't hand over a made-up one.

import { timeOfRound, verifyBeacon } from "./timelock";

/** The newest beacon, or null if it can't be had or doesn't check out. A post without one is still fine. */
export async function fetchWitness(): Promise<{ round: number; sig: string } | null> {
  try {
    const r = await fetch("/api/beacon", { cache: "no-store" });
    if (!r.ok) return null;
    const { round, sig } = (await r.json()) as { round?: unknown; sig?: unknown };
    if (typeof round !== "number" || typeof sig !== "string" || !verifyBeacon(round, sig)) return null;
    // If this browser's clock disagrees by more than a few minutes, leave the witness out rather than send one the site would refuse.
    const age = Date.now() - timeOfRound(round);
    if (age < -60_000 || age > 10 * 60_000) return null;
    return { round, sig };
  } catch {
    return null;
  }
}

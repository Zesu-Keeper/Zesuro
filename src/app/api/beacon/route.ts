import { NextResponse } from "next/server";
import { getBeacon } from "@/lib/beacon";
import { jsonError, rateLimited, tooMany } from "@/lib/http";
import { roundForTime } from "@/lib/timelock";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * The newest drand beacon this site could fetch and check: { round, sig }. A browser fetches it just before
 * posting, checks the signature itself against the pinned drand key, and includes it in the post as a witness
 * that the post was made no earlier than that round.
 */
export async function GET(req: Request) {
  try {
    if (rateLimited(req, "beacon", 60, 60_000)) return tooMany();
    // The round for this moment may not be published yet: take the one before it.
    const round = roundForTime(Date.now()) - 1;
    const sig = await getBeacon(round);
    if (!sig) return NextResponse.json({ error: "The public timer could not be reached right now." }, { status: 503, headers: { "cache-control": "no-store" } });
    return NextResponse.json({ round, sig }, { headers: { "cache-control": "no-store" } });
  } catch (e) {
    return jsonError(e);
  }
}

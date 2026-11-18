import { NextResponse } from "next/server";
import { voteEntry } from "@/lib/entries";
import { jsonError, rateLimited, readJson, tooMany } from "@/lib/http";
import { UUID } from "@/lib/opening";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** "Did it happen?" Body: { voter, value: 1 (happened) | -1 (didn't) | 0 (clear) }. Revealed entries only. */
export async function POST(req: Request, ctx: { params: Promise<{ uid: string }> }) {
  try {
    const { uid } = await ctx.params;
    if (
      rateLimited(req, "vote", 30, 60_000) ||
      rateLimited(req, "vote-day", 500, 86_400_000) ||
      // A few changes of mind per address per entry per day, and no more: fresh browser
      // tokens from one address can't stuff the count.
      (UUID.test(uid) && rateLimited(req, `outcome:${uid}`, 4, 86_400_000))
    )
      return tooMany();
    const body = await readJson(req, 1_000);
    return NextResponse.json(voteEntry(uid, body.voter, body.value, "outcome"));
  } catch (e) {
    return jsonError(e);
  }
}

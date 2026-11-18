import { NextResponse } from "next/server";
import { reportEntry } from "@/lib/entries";
import { jsonError, rateLimited, readJson, tooMany } from "@/lib/http";
import { requireTicket } from "@/lib/spam";
import { UUID } from "@/lib/opening";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Body: { voter }. One report per browser, and one per address per entry per day. */
export async function POST(req: Request, ctx: { params: Promise<{ uid: string }> }) {
  try {
    const { uid } = await ctx.params;
    if (
      rateLimited(req, "report", 10, 60_000) ||
      rateLimited(req, "report-day", 50, 86_400_000) ||
      (UUID.test(uid) && rateLimited(req, `report:e:${uid}`, 1, 86_400_000))
    )
      return tooMany();
    const body = await readJson(req, 1_000);
    requireTicket(body.ticket, body.website);
    return NextResponse.json(reportEntry(uid, body.voter));
  } catch (e) {
    return jsonError(e);
  }
}

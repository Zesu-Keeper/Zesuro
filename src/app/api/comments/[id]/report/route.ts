import { NextResponse } from "next/server";
import { reportComment } from "@/lib/comments";
import { jsonError, rateLimited, readJson, tooMany } from "@/lib/http";
import { requireTicket } from "@/lib/spam";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Body: { voter }. One report per browser, and one per address per comment per day. */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await ctx.params;
    const n = /^[1-9]\d{0,14}$/.test(id) ? Number(id) : 0;
    if (
      rateLimited(req, "report", 10, 60_000) ||
      rateLimited(req, "report-day", 50, 86_400_000) ||
      (n > 0 && rateLimited(req, `report:c:${n}`, 1, 86_400_000))
    )
      return tooMany();
    const body = await readJson(req, 1_000);
    requireTicket(body.ticket, body.website);
    return NextResponse.json(reportComment(n, body.voter));
  } catch (e) {
    return jsonError(e);
  }
}

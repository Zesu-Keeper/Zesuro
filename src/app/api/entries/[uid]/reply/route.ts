import { NextResponse } from "next/server";
import { jsonError, rateLimited, readJson, tooMany } from "@/lib/http";
import { postReply } from "@/lib/inbox";
import { requireTicket } from "@/lib/spam";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Body: { blob, ticket, website }. Stores a locked private reply to a post. */
export async function POST(req: Request, ctx: { params: Promise<{ uid: string }> }) {
  try {
    if (rateLimited(req, "reply", 6, 60_000) || rateLimited(req, "reply-day", 60, 86_400_000)) return tooMany();
    const { uid } = await ctx.params;
    const body = await readJson(req, 20_000);
    requireTicket(body.ticket, body.website);
    return NextResponse.json(postReply(uid, body.blob), { status: 201 });
  } catch (e) {
    return jsonError(e);
  }
}

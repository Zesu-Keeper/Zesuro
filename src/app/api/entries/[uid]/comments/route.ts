import { NextResponse } from "next/server";
import { addComment, listComments } from "@/lib/comments";
import { jsonError, rateLimited, readJson, tooMany } from "@/lib/http";
import { requireTicket } from "@/lib/spam";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** GET ?after=<last id you have> returns the next page, oldest first. */
export async function GET(req: Request, ctx: { params: Promise<{ uid: string }> }) {
  try {
    if (rateLimited(req, "read", 300, 60_000)) return tooMany();
    const { uid } = await ctx.params;
    const u = new URL(req.url);
    const after = Number(u.searchParams.get("after")) || 0;
    return NextResponse.json(listComments(uid, { after }));
  } catch (e) {
    return jsonError(e);
  }
}

/** Body: { uid, text, tag }. Comments are permanent, so posting is limited per minute and per day. */
export async function POST(req: Request, ctx: { params: Promise<{ uid: string }> }) {
  try {
    if (rateLimited(req, "comment", 5, 60_000) || rateLimited(req, "comment-day", 50, 86_400_000))
      return tooMany();
    const { uid } = await ctx.params;
    const body = await readJson(req, 12_000);
    requireTicket(body.ticket, body.website);
    return NextResponse.json({ comment: addComment(uid, body) }, { status: 201 });
  } catch (e) {
    return jsonError(e);
  }
}

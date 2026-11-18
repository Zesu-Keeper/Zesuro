import { NextResponse } from "next/server";
import { joinInvite } from "@/lib/chat";
import { jsonError, rateLimited, readJson, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Body: { room, join, auth }. Uses up one opening of the link. */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    if (rateLimited(req, "chat-join", 20, 60_000)) return tooMany();
    const { id } = await ctx.params;
    return NextResponse.json(joinInvite(id, await readJson(req, 4_000)), { status: 201 });
  } catch (e) {
    return jsonError(e);
  }
}

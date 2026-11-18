import { NextResponse } from "next/server";
import { closeInvite, inviteHello, inviteStatus } from "@/lib/chat";
import { jsonError, rateLimited, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const noStore = { "cache-control": "no-store" };

/**
 * With the creator's x-chat-owner header: who has joined. Without it: the creator's half of
 * the key exchange, for someone opening the link.
 */
export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    if (rateLimited(req, "chat-invite", 120, 60_000)) return tooMany();
    const { id } = await ctx.params;
    const owner = req.headers.get("x-chat-owner");
    return NextResponse.json(owner ? inviteStatus(id, owner) : inviteHello(id), { headers: noStore });
  } catch (e) {
    return jsonError(e);
  }
}

/** The creator cancels the link. */
export async function DELETE(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    if (rateLimited(req, "chat-invite", 120, 60_000)) return tooMany();
    const { id } = await ctx.params;
    closeInvite(id, req.headers.get("x-chat-owner"));
    return NextResponse.json({ ok: true });
  } catch (e) {
    return jsonError(e);
  }
}

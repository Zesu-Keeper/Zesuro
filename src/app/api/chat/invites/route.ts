import { NextResponse } from "next/server";
import { createInvite } from "@/lib/chat";
import { jsonError, rateLimited, readJson, tooMany } from "@/lib/http";
import { requireTicket } from "@/lib/spam";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Body: { id, owner, hello, maxUses, ticket }. Creates a private chat link. */
export async function POST(req: Request) {
  try {
    if (rateLimited(req, "chat-new", 10, 3_600_000) || rateLimited(req, "chat-new-day", 40, 86_400_000))
      return tooMany();
    const body = await readJson(req, 24_000);
    requireTicket(body.ticket, body.website);
    return NextResponse.json(createInvite(body), { status: 201 });
  } catch (e) {
    return jsonError(e);
  }
}

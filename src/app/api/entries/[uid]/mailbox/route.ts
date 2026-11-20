import { NextResponse } from "next/server";
import { jsonError, rateLimited, tooMany } from "@/lib/http";
import { getMailbox } from "@/lib/inbox";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** A post's mailbox public keys. Their fingerprint is in the record (hash v5), so a reader can check them. */
export async function GET(req: Request, ctx: { params: Promise<{ uid: string }> }) {
  try {
    if (rateLimited(req, "read", 300, 60_000)) return tooMany();
    const { uid } = await ctx.params;
    const m = getMailbox(uid);
    if (!m) return NextResponse.json({ error: "This post doesn't take private replies" }, { status: 404 });
    return NextResponse.json(m);
  } catch (e) {
    return jsonError(e);
  }
}

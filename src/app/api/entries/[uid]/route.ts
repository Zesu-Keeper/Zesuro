import { NextResponse } from "next/server";
import { getEntry } from "@/lib/entries";
import { jsonError, rateLimited, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request, ctx: { params: Promise<{ uid: string }> }) {
  try {
    if (rateLimited(req, "read", 300, 60_000)) return tooMany();
    const { uid } = await ctx.params;
    const entry = getEntry(uid);
    if (!entry) return NextResponse.json({ error: "Not found" }, { status: 404 });
    return NextResponse.json({ entry });
  } catch (e) {
    return jsonError(e);
  }
}

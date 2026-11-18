import { NextResponse } from "next/server";
import { revealEntry } from "@/lib/entries";
import { jsonError, rateLimited, readJson, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request, ctx: { params: Promise<{ uid: string }> }) {
  try {
    if (rateLimited(req, "reveal", 30, 60_000)) return tooMany();
    const { uid } = await ctx.params;
    const body = await readJson(req, 100_000);
    const entry = await revealEntry(uid, body);
    return NextResponse.json({ entry });
  } catch (e) {
    return jsonError(e);
  }
}

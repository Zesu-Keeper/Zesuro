import { NextResponse } from "next/server";
import { addWitness } from "@/lib/anchors";
import { jsonError, rateLimited, readJson, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Body: { key, at, sig }. A mirror's countersignature on this anchor. See lib/anchors.ts. */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    if (rateLimited(req, "witness", 120, 60_000)) return tooMany();
    const id = Number((await ctx.params).id);
    return NextResponse.json(addWitness(id, await readJson(req, 2_000)), { status: 201 });
  } catch (e) {
    return jsonError(e);
  }
}

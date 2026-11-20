import { NextResponse } from "next/server";
import { jsonError, rateLimited, tooMany } from "@/lib/http";
import { newsroomList } from "@/lib/newsroom";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** ?domain=example.org: that newsroom's published list of journalists (lib/newsroom.ts). */
export async function GET(req: Request) {
  try {
    if (rateLimited(req, "newsroom", 30, 60_000)) return tooMany();
    const domain = new URL(req.url).searchParams.get("domain") ?? "";
    return NextResponse.json(await newsroomList(domain), { headers: { "cache-control": "no-store" } });
  } catch (e) {
    return jsonError(e);
  }
}

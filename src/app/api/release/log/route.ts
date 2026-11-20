import { NextResponse } from "next/server";
import { jsonError, rateLimited, tooMany } from "@/lib/http";
import { readReleaseLog } from "@/lib/release-log";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Every signed release this site has served, oldest first, hash-linked (lib/release-log.ts). ?after=<seq>. */
export function GET(req: Request) {
  try {
    if (rateLimited(req, "release", 60, 60_000)) return tooMany();
    const after = Number(new URL(req.url).searchParams.get("after") ?? "0") || 0;
    return NextResponse.json(readReleaseLog(after, 200), { headers: { "cache-control": "no-store" } });
  } catch (e) {
    return jsonError(e);
  }
}

import { NextResponse } from "next/server";
import { listLog } from "@/lib/entries";
import { jsonError, rateLimited, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** The whole record, a page at a time: ?after=<seq>&limit=<n up to 1000>. See scripts/verify-log.mjs. */
export function GET(req: Request) {
  try {
    if (rateLimited(req, "log", 60, 60_000)) return tooMany();
    const u = new URL(req.url);
    const entries = listLog(Number(u.searchParams.get("after") ?? "0"), Number(u.searchParams.get("limit") ?? "500"));
    return NextResponse.json({ entries });
  } catch (e) {
    return jsonError(e);
  }
}

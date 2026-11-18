import { NextResponse } from "next/server";
import { listCommentLog } from "@/lib/comments";
import { jsonError, rateLimited, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** The comment chain, a page at a time: ?after=<id>&limit=<n up to 1000>. */
export function GET(req: Request) {
  try {
    if (rateLimited(req, "log", 60, 60_000)) return tooMany();
    const u = new URL(req.url);
    const comments = listCommentLog(Number(u.searchParams.get("after") ?? "0"), Number(u.searchParams.get("limit") ?? "500"));
    return NextResponse.json({ comments });
  } catch (e) {
    return jsonError(e);
  }
}

import { NextResponse } from "next/server";
import { jsonError, rateLimited, tooMany } from "@/lib/http";
import { readInbox } from "@/lib/inbox";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** All locked private replies after ?after=<id>. The same for everyone: nobody's request says which post is theirs. */
export function GET(req: Request) {
  try {
    if (rateLimited(req, "inbox", 120, 60_000)) return tooMany();
    const after = Number(new URL(req.url).searchParams.get("after") ?? "0") || 0;
    return NextResponse.json(readInbox(after), { headers: { "cache-control": "no-store" } });
  } catch (e) {
    return jsonError(e);
  }
}

import { NextResponse } from "next/server";
import { anchorPublicKey, listAnchors } from "@/lib/anchors";
import { jsonError, rateLimited, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Signed chain tips, newest first. ?before=<id>&limit=<n> pages back. */
export function GET(req: Request) {
  try {
    if (rateLimited(req, "anchors", 60, 60_000)) return tooMany();
    const u = new URL(req.url);
    return NextResponse.json({
      publicKey: anchorPublicKey(),
      anchors: listAnchors(Number(u.searchParams.get("before") ?? "0"), Number(u.searchParams.get("limit") ?? "50")),
    });
  } catch (e) {
    return jsonError(e);
  }
}

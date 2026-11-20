import fs from "node:fs";
import path from "node:path";
import { NextResponse } from "next/server";
import { jsonError, rateLimited, tooMany } from "@/lib/http";
import { syncReleaseLog } from "@/lib/release-log";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * The root-signed list of hashes of this release's scripts and stylesheets: data/release.json as
 * made by scripts/release.mjs. Nothing here is trusted until a checker verifies it against a root
 * key it pinned itself (scripts/code-check.mjs). 404 until a release has been signed.
 */
export function GET(req: Request) {
  try {
    if (rateLimited(req, "release", 60, 60_000)) return tooMany();
    syncReleaseLog(); // the release being served is always the newest entry in the public release log
    let text: string;
    try {
      text = fs.readFileSync(path.join(process.cwd(), "data", "release.json"), "utf8");
    } catch {
      return NextResponse.json({ error: "No release has been signed" }, { status: 404 });
    }
    return new NextResponse(text, { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
  } catch (e) {
    return jsonError(e);
  }
}

import fs from "node:fs";
import path from "node:path";
import { NextResponse } from "next/server";
import { jsonError, rateLimited, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * The root-signed directory of genuine mirrors and known impostor sites: data/sites.json as made by
 * scripts/sites.mjs. Nothing here is trusted until a checker verifies it against a root key it pinned
 * itself. 404 until one has been signed.
 */
export function GET(req: Request) {
  try {
    if (rateLimited(req, "sites", 60, 60_000)) return tooMany();
    let text: string;
    try {
      text = fs.readFileSync(path.join(process.cwd(), "data", "sites.json"), "utf8");
    } catch {
      return NextResponse.json({ error: "No sites list has been signed" }, { status: 404 });
    }
    return new NextResponse(text, { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
  } catch (e) {
    return jsonError(e);
  }
}

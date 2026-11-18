import fs from "node:fs";
import path from "node:path";
import { NextResponse } from "next/server";
import { jsonError, rateLimited, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Which servers the root key has authorised to write this record: data/authority.json, exactly as
 * root.mjs made it. Mirrors and verifiers check it against a root key they pinned themselves, so
 * nothing served here is trusted until it verifies. 404 until a root key has delegated.
 */
export function GET(req: Request) {
  try {
    if (rateLimited(req, "authority", 60, 60_000)) return tooMany();
    let text: string;
    try {
      text = fs.readFileSync(path.join(process.cwd(), "data", "authority.json"), "utf8");
    } catch {
      return NextResponse.json({ error: "No authority has been published" }, { status: 404 });
    }
    return new NextResponse(text, { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
  } catch (e) {
    return jsonError(e);
  }
}

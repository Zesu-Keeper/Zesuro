import fs from "node:fs";
import { Readable } from "node:stream";
import { authoriseStandby, snapshotPath } from "@/lib/snapshots";
import { jsonError, rateLimited, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** An encrypted snapshot, for an accepted standby only (signed request headers; see lib/snapshots.ts). */
export async function GET(req: Request, ctx: { params: Promise<{ name: string }> }) {
  try {
    if (rateLimited(req, "snapshot-file", 20, 3_600_000)) return tooMany();
    const name = (await ctx.params).name;
    authoriseStandby(req, name);
    const p = snapshotPath(name);
    if (!p) return new Response('{"error":"Not found"}', { status: 404, headers: { "content-type": "application/json" } });
    return new Response(Readable.toWeb(fs.createReadStream(p)) as ReadableStream, {
      headers: { "content-type": "application/octet-stream", "content-length": String(fs.statSync(p).size), "cache-control": "no-store" },
    });
  } catch (e) {
    return jsonError(e);
  }
}

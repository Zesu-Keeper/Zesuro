import { latestManifest } from "@/lib/snapshots";
import { jsonError, rateLimited, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** The newest snapshot's signed manifest: { manifest, sig }. Public; the snapshot itself is not. */
export function GET(req: Request) {
  try {
    if (rateLimited(req, "snapshot-manifest", 60, 60_000)) return tooMany();
    const text = latestManifest();
    if (!text) return new Response('{"error":"No snapshot has been made"}', { status: 404, headers: { "content-type": "application/json" } });
    return new Response(text, { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
  } catch (e) {
    return jsonError(e);
  }
}

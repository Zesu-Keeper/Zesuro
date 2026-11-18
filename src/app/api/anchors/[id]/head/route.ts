import { getAnchor } from "@/lib/anchors";
import { rateLimited, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** The exact text that was signed and timestamped (SHA-256 of it is what OpenTimestamps holds). */
export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  if (rateLimited(req, "anchors", 60, 60_000)) return tooMany();
  const a = getAnchor(Number((await ctx.params).id));
  if (!a) return new Response("Not found", { status: 404 });
  return new Response(a.head, { headers: { "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff" } });
}

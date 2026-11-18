import { NextResponse } from "next/server";
import { verifyComments } from "@/lib/comments";
import { verifyChain } from "@/lib/entries";
import { rateLimited, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Publishes the current chain tip. Anchoring this value to independent timestamp
// services (OpenTimestamps, RFC 3161) is the next milestone.
//
// Verifying walks every entry, so the result is cached briefly: a stream of requests
// must not be able to keep the server busy.
type Body = ReturnType<typeof verifyChain> & { comments: ReturnType<typeof verifyComments> };
let cached: { at: number; body: Body } | null = null;
const TTL_MS = 10_000;

export function GET(req: Request) {
  if (rateLimited(req, "chain", 30, 60_000)) return tooMany();
  const now = Date.now();
  if (!cached || now - cached.at > TTL_MS) {
    const entries = verifyChain();
    const comments = verifyComments();
    // `ok` covers both chains; the entry chain's count and tip stay at the top level.
    cached = { at: now, body: { ...entries, ok: entries.ok && comments.ok, comments } };
  }
  return NextResponse.json(cached.body);
}

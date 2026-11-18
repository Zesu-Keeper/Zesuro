import { NextResponse } from "next/server";
import { rateLimited, tooMany } from "@/lib/http";
import { issueTicket } from "@/lib/spam";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** A form fetches this when it opens and sends it back with the post. See lib/spam.ts. */
export function GET(req: Request) {
  if (rateLimited(req, "ticket", 60, 60_000)) return tooMany();
  return NextResponse.json({ ticket: issueTicket() });
}

import { NextResponse } from "next/server";
import { listEntries, sealEntry, type Status } from "@/lib/entries";
import { jsonError, rateLimited, readJson, tooMany } from "@/lib/http";
import { requireTicket } from "@/lib/spam";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  try {
    if (rateLimited(req, "read", 300, 60_000)) return tooMany();
    const u = new URL(req.url);
    const s = u.searchParams.get("status");
    const status =
      s === "anonymous" || s === "revealed" || s === "unknown" ? (s as Status) : undefined;
    const limit = Number(u.searchParams.get("limit")) || 50;
    const before = Number(u.searchParams.get("before")) || undefined;
    const q = u.searchParams.get("q") || undefined;
    const from = u.searchParams.get("from") || undefined;
    const to = u.searchParams.get("to") || undefined;
    const sort = u.searchParams.get("sort") === "top" ? "top" : "new";
    const offset = Number(u.searchParams.get("offset")) || 0;
    return NextResponse.json({
      entries: listEntries({ status, sort, offset, limit, beforeSeq: before, q, from, to }),
    });
  } catch (e) {
    return jsonError(e);
  }
}

export async function POST(req: Request) {
  try {
    // Entries are permanent, so sealing is limited both per minute and per day.
    if (rateLimited(req, "seal", 10, 60_000) || rateLimited(req, "seal-day", 200, 86_400_000))
      return tooMany();
    const body = await readJson(req, 100_000);
    requireTicket(body.ticket, body.website);
    const entry = await sealEntry({
      uid: body.uid,
      title: body.title,
      placeMode: body.placeMode,
      place: body.place,
      secretCommit: body.secretCommit,
      secret: body.secret,
      secretBlob: body.secretBlob,
      text: body.text,
      commitment: body.commitment,
      nonce: body.nonce,
      mode: body.mode,
      revealAt: body.revealAt,
      deadlineAt: body.deadlineAt,
      opening: body.opening,
      timelock: body.timelock,
      commitV: body.commitV,
      revealPublic: body.revealPublic,
      delay: body.delay,
    });
    // A delayed post is not in the record yet: it is only acknowledged.
    if ("pending" in entry) return NextResponse.json({ pending: entry }, { status: 202 });
    return NextResponse.json({ entry }, { status: 201 });
  } catch (e) {
    return jsonError(e);
  }
}

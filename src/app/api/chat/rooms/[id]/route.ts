import { NextResponse } from "next/server";
import { deleteRoom, postMessage, readRoom, setRoomTtl } from "@/lib/chat";
import { jsonError, rateLimited, readJson, tooMany } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const noStore = { "cache-control": "no-store" };
type Ctx = { params: Promise<{ id: string }> };
const auth = (req: Request) => req.headers.get("x-chat-auth");

/** Encrypted messages after ?after=<id>. Needs the room's x-chat-auth header. */
export async function GET(req: Request, ctx: Ctx) {
  try {
    if (rateLimited(req, "chat-read", 240, 60_000)) return tooMany();
    const { id } = await ctx.params;
    const after = Number(new URL(req.url).searchParams.get("after") ?? "0");
    return NextResponse.json(readRoom(id, auth(req), after), { headers: noStore });
  } catch (e) {
    return jsonError(e);
  }
}

/** Body: { blob }. */
export async function POST(req: Request, ctx: Ctx) {
  try {
    if (rateLimited(req, "chat-send", 60, 60_000)) return tooMany();
    const { id } = await ctx.params;
    const body = await readJson(req, 50_000);
    return NextResponse.json(postMessage(id, auth(req), body.blob), { status: 201 });
  } catch (e) {
    return jsonError(e);
  }
}

/** Body: { ttl } in milliseconds; 0 turns the auto-delete timer off. */
export async function PATCH(req: Request, ctx: Ctx) {
  try {
    if (rateLimited(req, "chat-send", 60, 60_000)) return tooMany();
    const { id } = await ctx.params;
    const body = await readJson(req, 1_000);
    return NextResponse.json(setRoomTtl(id, auth(req), body.ttl));
  } catch (e) {
    return jsonError(e);
  }
}

/** Deletes every message, for both sides. */
export async function DELETE(req: Request, ctx: Ctx) {
  try {
    if (rateLimited(req, "chat-send", 60, 60_000)) return tooMany();
    const { id } = await ctx.params;
    deleteRoom(id, auth(req));
    return NextResponse.json({ ok: true });
  } catch (e) {
    return jsonError(e);
  }
}

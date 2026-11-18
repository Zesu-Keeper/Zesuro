import { NextResponse } from "next/server";
import { EntryError } from "./entries";
import { groupV6 } from "./ip";

export function jsonError(e: unknown) {
  if (e instanceof EntryError) {
    return NextResponse.json({ error: e.message }, { status: e.status });
  }
  console.error(e);
  return NextResponse.json({ error: "Something went wrong" }, { status: 500 });
}

/**
 * Who is calling? Forwarding headers are client-controlled unless a trusted proxy sets them,
 * so they are ignored by default. Set TRUST_PROXY=cloudflare when the app sits behind
 * Cloudflare (or a Cloudflare Tunnel), or TRUST_PROXY=xff behind a single proxy that
 * appends the real address as the LAST X-Forwarded-For entry.
 */
export function clientIp(h: Headers): string {
  const mode = process.env.TRUST_PROXY;
  if (mode === "cloudflare") return groupV6(h.get("cf-connecting-ip")?.trim() || "unknown");
  if (mode === "xff") {
    // Visitors arriving through the Tor onion service all reach the proxy from this machine;
    // the proxy marks them (and strips the mark from everyone else's requests).
    if (h.get("x-onion") === "1") return "onion";
    const parts = (h.get("x-forwarded-for") ?? "").split(",");
    return groupV6(parts[parts.length - 1]?.trim() || "unknown");
  }
  return "direct";
}

// Tiny in-memory limiter for the prototype. Replace with a proper edge limiter before launch.
const MAX_KEYS = 20_000;
const hits = new Map<string, number[]>();
let lastSweep = 0;

function sweep(now: number) {
  if (now - lastSweep < 30_000 && hits.size < MAX_KEYS) return;
  lastSweep = now;
  for (const [k, v] of hits) {
    // Entries older than the longest window we use (a day) can go.
    if (v.length === 0 || now - v[v.length - 1] > 86_400_000) hits.delete(k);
  }
  // Still too big (a flood of distinct callers): drop the oldest keys.
  if (hits.size >= MAX_KEYS) {
    for (const k of hits.keys()) {
      hits.delete(k);
      if (hits.size < MAX_KEYS * 0.8) break;
    }
  }
}

export function rateLimitedHeaders(
  h: Headers,
  bucket: string,
  max: number,
  windowMs: number,
): boolean {
  // Test switch for the smoke test. Never honoured in production builds.
  if (process.env.RATE_LIMIT_OFF === "1" && process.env.NODE_ENV !== "production") return false;
  const ip = clientIp(h);
  const key = `${bucket}:${ip}`;
  const now = Date.now();
  sweep(now);
  const recent = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
  // Tor users are told apart by nothing, so they share one bucket: a larger one.
  if (recent.length >= (ip === "onion" ? max * 25 : max)) {
    hits.set(key, recent);
    return true;
  }
  recent.push(now);
  hits.set(key, recent);
  return false;
}

export function rateLimited(req: Request, bucket: string, max: number, windowMs: number) {
  return rateLimitedHeaders(req.headers, bucket, max, windowMs);
}

export const tooMany = () =>
  NextResponse.json({ error: "Slow down a moment" }, { status: 429, headers: { "retry-after": "30" } });

/**
 * Reads a JSON body with a hard size cap. Requires application/json, which also forces
 * browsers to send a CORS preflight for requests from other websites.
 */
export async function readJson(req: Request, maxBytes: number): Promise<Record<string, unknown>> {
  const type = req.headers.get("content-type") ?? "";
  if (!/^application\/json\b/i.test(type)) throw new EntryError("Send JSON", 415);
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (declared > maxBytes) throw new EntryError("That is too large", 413);
  if (!req.body) throw new EntryError("Invalid request");
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new EntryError("That is too large", 413);
    }
    chunks.push(value);
  }
  try {
    const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return parsed as Record<string, unknown>;
  } catch {
    throw new EntryError("Invalid request");
  }
}

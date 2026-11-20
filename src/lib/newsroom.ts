// Fetches a newsroom's list of journalists from https://<domain>/.well-known/zesuro-journalists.json, carefully: only
// public internet addresses, no redirects, a short time limit, a small size limit, and a short cache.

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { EntryError } from "./errors";

const DOMAIN = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const cache = new Map<string, { at: number; body: { journalists: { name: string; key: string }[] } }>();

function privateAddress(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split(".").map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  return v === "::1" || v === "::" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80") || v.startsWith("::ffff:");
}

export async function newsroomList(rawDomain: string): Promise<{ journalists: { name: string; key: string }[] }> {
  const domain = rawDomain.trim().toLowerCase();
  if (!DOMAIN.test(domain)) throw new EntryError("That is not a newsroom address");
  const hit = cache.get(domain);
  if (hit && Date.now() - hit.at < 10 * 60_000) return hit.body;
  const addrs = await lookup(domain, { all: true }).catch(() => []);
  if (!addrs.length || addrs.some((a) => privateAddress(a.address))) throw new EntryError("That newsroom address can't be checked", 400);
  const res = await fetch(`https://${domain}/.well-known/zesuro-journalists.json`, {
    redirect: "error",
    signal: AbortSignal.timeout(6_000),
    headers: { accept: "application/json" },
  }).catch(() => null);
  if (!res || !res.ok) throw new EntryError("That newsroom doesn't publish a list of journalists", 404);
  const text = await res.text();
  if (text.length > 64_000) throw new EntryError("That newsroom's list is too large", 400);
  let journalists: { name: string; key: string }[] = [];
  try {
    const j = JSON.parse(text) as { journalists?: unknown };
    if (Array.isArray(j.journalists))
      journalists = j.journalists
        .filter((x): x is { name: string; key: string } => !!x && typeof (x as { name: unknown }).name === "string" && typeof (x as { key: unknown }).key === "string")
        .slice(0, 500)
        .map((x) => ({ name: x.name.slice(0, 80), key: x.key.slice(0, 64) }));
  } catch {
    throw new EntryError("That newsroom's list is not valid", 400);
  }
  const body = { journalists };
  cache.set(domain, { at: Date.now(), body });
  return body;
}

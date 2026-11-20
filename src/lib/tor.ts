/** True if this request came through the site's onion service (nginx marks it, and the host is the .onion name). */
export function viaTor(h: { get(name: string): string | null }): boolean {
  return h.get("x-onion") === "1" || (h.get("host") ?? "").toLowerCase().replace(/:\d+$/, "").endsWith(".onion");
}

/** The site's onion address, if the operator set one (ONION_ADDRESS). */
export function onionAddress(): string | null {
  const a = (process.env.ONION_ADDRESS ?? "").trim().toLowerCase();
  return /^[a-z2-7]{56}\.onion$/.test(a) ? a : null;
}

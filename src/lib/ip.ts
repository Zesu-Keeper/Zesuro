/**
 * One person with an IPv6 connection holds billions of addresses (a /64 is the smallest
 * normal allocation), so limits are applied to the /64, not the single address.
 */
export function groupV6(a: string): string {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(a);
  if (mapped) return mapped[1];
  if (!a.includes(":")) return a;
  const [head, tail, ...rest] = a.split("::");
  if (rest.length) return a;
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = tail === undefined ? h : [...h, ...Array<string>(Math.max(8 - h.length - t.length, 0)).fill("0"), ...t];
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return a;
  return groups.slice(0, 4).map((g) => g.toLowerCase().replace(/^0+(?=.)/, "")).join(":") + "::/64";
}


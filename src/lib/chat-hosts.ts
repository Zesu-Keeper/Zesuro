// Private chats can be served from throwaway addresses that never mention Zesuro: a different domain, and a
// random sub-address for every chat (https://k3x9...random.example.net/). The operator lists the plain domains
// in CHAT_HOSTS (comma separated). Anything that is saved in a browser then names only that random address.
//
//   "apex"  the bare domain: sends the visitor to a fresh random address
//   "chat"  a random address under it: serves only the chat, with nothing that says what site it is
//   "main"  the normal site

export type HostKind = "main" | "apex" | "chat";

const HOST = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** The plain chat domains from CHAT_HOSTS, lower case, bad entries dropped. */
export function parseChatApexes(raw: string | undefined | null): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => HOST.test(s));
}

export const chatApexes = (): string[] => parseChatApexes(process.env.CHAT_HOSTS);

/** Which kind of address a request came to. `host` is the Host header (a port is ignored). */
export function hostKind(host: string | null | undefined, apexes: string[] = chatApexes()): HostKind {
  if (!host) return "main";
  const h = host.toLowerCase().replace(/:\d+$/, "").replace(/\.$/, "");
  for (const a of apexes) {
    if (h === a) return "apex";
    if (h.endsWith("." + a) && /^[a-z0-9-]{1,63}$/.test(h.slice(0, -(a.length + 1)))) return "chat";
  }
  return "main";
}

const ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";

/** A random sub-address label: 24 characters, about 124 bits. */
export function randomLabel(): string {
  const b = crypto.getRandomValues(new Uint8Array(24));
  let s = "";
  // Rejection-free: 256 is not a multiple of 36, so keep the bias negligible by using the low 6 bits and skipping 36 and up.
  for (let i = 0; s.length < 24; i++) {
    const v = i < b.length ? b[i] & 63 : crypto.getRandomValues(new Uint8Array(1))[0] & 63;
    if (v < 36) s += ALPHABET[v];
  }
  return s;
}

/** A fresh random chat address under a randomly chosen one of the operator's domains. */
export function randomChatOrigin(apexes: string[]): string | null {
  if (!apexes.length) return null;
  const a = apexes[crypto.getRandomValues(new Uint32Array(1))[0] % apexes.length];
  return `https://${randomLabel()}.${a}`;
}

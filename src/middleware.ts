import { NextResponse, type NextRequest } from "next/server";
import { CHAT_HEADER, chatApexes, hostKind, randomChatOrigin } from "@/lib/chat-hosts";

// Content-Security-Policy with a per-request nonce. The author's secret key lives in browser
// storage, so a script-injection bug would be a key-theft bug; this is the second line of
// defence behind React's escaping.
export function middleware(req: NextRequest) {
  // Private chats on their own throwaway addresses (lib/chat-hosts.ts).
  const kind = hostKind(req.headers.get("host"));
  if (kind === "apex") {
    // The bare chat domain only ever hands out a fresh random address.
    const to = randomChatOrigin(chatApexes());
    const r = NextResponse.redirect(`${to}/`, 302);
    r.headers.set("cache-control", "no-store");
    return r;
  }
  if (kind === "chat") {
    const path = req.nextUrl.pathname;
    // Only the chat itself exists here. Everything else looks like nothing is there.
    if (path !== "/" && path !== "/chat") return new NextResponse(null, { status: 404, headers: { "cache-control": "no-store" } });
    const res = chatShell(req);
    return res;
  }
  return page(req, false);
}

/** The page response with the content security policy. `chat` is true for a private chat address. */
function page(req: NextRequest, chat: boolean) {
  const nonce = btoa(crypto.randomUUID());
  const dev = process.env.NODE_ENV !== "production";
  const csp = [
    "default-src 'self'",
    // 'strict-dynamic' lets the nonced Next.js bootstrap load its own chunks.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    // Leaflet positions the map with inline styles.
    "style-src 'self' 'unsafe-inline'",
    // Map tiles come through this site (see nginx), so readers' addresses never reach a map provider.
    "img-src 'self' data: blob:",
    "font-src 'self'",
    `connect-src 'self'${dev ? " ws: wss:" : ""}`,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  const headers = new Headers(req.headers);
  // The marker is set here and only here: a visitor can't claim to be on a private address by sending it.
  headers.delete(CHAT_HEADER);
  if (chat) headers.set(CHAT_HEADER, "1");
  headers.set("x-nonce", nonce);
  headers.set("content-security-policy", csp);
  // On a private address "/" is the chat too: app/page.tsx serves it, so the host name is still the real one.
  const res = NextResponse.next({ request: { headers } });
  res.headers.set("content-security-policy", csp);
  if (chat) {
    // Nothing from a chat address is kept by the browser or indexed.
    res.headers.set("cache-control", "no-store");
    res.headers.set("x-robots-tag", "noindex, nofollow, noarchive");
  }
  return res;
}

const chatShell = (req: NextRequest) => page(req, true);

export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};

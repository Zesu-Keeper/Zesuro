import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import Link from "next/link";
import { hostKind } from "@/lib/chat-hosts";
import "./globals.css";

// Every page is rendered per request so it can carry that request's CSP nonce.
export const dynamic = "force-dynamic";

const siteMetadata: Metadata = {
  title: "Zesuro",
  description:
    "Say it now. It's recorded with its exact time. You decide when your name is attached.",
};

// On a private chat address nothing says what site this is.
export async function generateMetadata(): Promise<Metadata> {
  if (hostKind((await headers()).get("host")) === "chat")
    return { title: "Notes", description: "", robots: { index: false, follow: false } };
  return siteMetadata;
}

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  if (hostKind((await headers()).get("host")) === "chat")
    return (
      <html lang="en">
        <body>
          <div className="shell">{children}</div>
        </body>
      </html>
    );
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <header className="top">
            <Link href="/" className="brand">
              zes<span>u</span>ro
            </Link>
            <nav className="nav" aria-label="Main">
              <Link href="/say" className="cta">Say it</Link>
              <Link href="/">Popular</Link>
              <Link href="/new">Latest</Link>
              <Link href="/called">Came true</Link>
              <Link href="/chat">Private chat</Link>
              <Link href="/mine">My posts</Link>
              <Link href="/help">Help</Link>
            </nav>
          </header>
          {children}
          <p className="foot">
            Say something now and its exact time is recorded. You choose if and when your name is shown. <Link href="/help">Help</Link>
          </p>
        </div>
      </body>
    </html>
  );
}

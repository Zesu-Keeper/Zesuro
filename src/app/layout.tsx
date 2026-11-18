import type { Metadata, Viewport } from "next";
import Link from "next/link";
import "./globals.css";

// Every page is rendered per request so it can carry that request's CSP nonce.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Zesuro",
  description:
    "Say it now. It's recorded with its exact time. You decide when your name is attached.",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
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
            Zesuro records who said what, and when, anonymously, but with verification.
          </p>
        </div>
      </body>
    </html>
  );
}

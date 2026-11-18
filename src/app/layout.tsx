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
              <Link href="/">Record</Link>
              <Link href="/new">New</Link>
              <Link href="/called">Called it</Link>
              <Link href="/say">Say it</Link>
              <Link href="/chat">Chat</Link>
              <Link href="/mine">Mine</Link>
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

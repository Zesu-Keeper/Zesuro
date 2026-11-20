const prod = process.env.NODE_ENV === "production";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    const common = [
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "X-Frame-Options", value: "DENY" },
      // No referrer at all: a linked site must not learn that a visitor came from here.
      { key: "Referrer-Policy", value: "no-referrer" },
      { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
      {
        key: "Permissions-Policy",
        value: "camera=(), microphone=(), payment=(), usb=(), geolocation=(self)",
      },
      // Only over HTTPS; browsers ignore it on plain http. No preload or subdomains yet.
      ...(prod ? [{ key: "Strict-Transport-Security", value: "max-age=31536000" }] : []),
    ];
    return [
      { source: "/:path*", headers: common },
      // API answers are live and sometimes private to the moment: never cache them.
      { source: "/api/:path*", headers: [{ key: "Cache-Control", value: "no-store" }] },
      // The chat page is never kept in the browser's cache.
      { source: "/chat", headers: [{ key: "Cache-Control", value: "no-store" }] },
    ];
  },
};

export default nextConfig;

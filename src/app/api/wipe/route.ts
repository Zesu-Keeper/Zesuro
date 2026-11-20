export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Answers with a Clear-Site-Data header, which tells the browser to throw away what it saved for this site.
 * scope=cache: its saved copies of pages and files. scope=all: also cookies and all stored data
 * (which includes the keys to your own posts), so the page only asks for it after a clear warning.
 */
export async function GET(req: Request) {
  const all = new URL(req.url).searchParams.get("scope") === "all";
  return new Response(null, {
    status: 204,
    headers: {
      "Clear-Site-Data": all ? '"cache", "cookies", "storage"' : '"cache"',
      "Cache-Control": "no-store",
    },
  });
}

import Link from "next/link";
import EntryCard from "@/components/EntryCard";
import { listCalled } from "@/lib/entries";

export const dynamic = "force-dynamic";
export const metadata = { title: "Called It · Zesuro" };

const PAGE = 25;
const MAX_PAGE = 400; // offset ceiling matches listCalled's

export default async function Called({ searchParams }: { searchParams: Promise<{ page?: string }> }) {
  const sp = await searchParams;
  const page = Math.min(Math.max(Math.floor(Number(sp.page)) || 1, 1), MAX_PAGE);
  const rows = listCalled({ offset: (page - 1) * PAGE, limit: PAGE + 1 });
  const more = rows.length > PAGE && page < MAX_PAGE;
  const shown = rows.slice(0, PAGE);
  const href = (p: number) => (p > 1 ? `/called?page=${p}` : "/called");

  return (
    <main>
      <h1>Called it</h1>
      <p className="lede">
        Revealed entries, ranked by how many people say it really happened. Anyone can vote once
        an entry is revealed, one vote per browser.
      </p>
      {shown.length === 0 ? (
        <p className="empty">
          {page > 1 ? (
            <>
              Nothing on this page. <Link href="/called">Back to the start.</Link>
            </>
          ) : (
            "No votes yet. Open a revealed entry and say whether it happened."
          )}
        </p>
      ) : (
        shown.map((e, i) => (
          <div key={e.uid}>
            <p className="count" style={{ margin: "12px 0 -4px" }}>
              #{(page - 1) * PAGE + i + 1} · {e.happened.toLocaleString("en")} say it happened,{" "}
              {e.notHappened.toLocaleString("en")} say it didn&apos;t
            </p>
            <EntryCard e={e} />
          </div>
        ))
      )}
      {page > 1 || more ? (
        <div className="row" style={{ justifyContent: "center" }}>
          {page > 1 ? (
            <Link className="btn" href={href(page - 1)}>
              Previous
            </Link>
          ) : null}
          {more ? (
            <Link className="btn" href={href(page + 1)}>
              Next
            </Link>
          ) : null}
        </div>
      ) : null}
    </main>
  );
}

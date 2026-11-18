import Link from "next/link";
import { notFound } from "next/navigation";
import EntryCard from "@/components/EntryCard";
import { getEntry, listSimilar } from "@/lib/entries";

export const dynamic = "force-dynamic";
export const metadata = { title: "Similar entries · Zesuro" };

const PAGE = 25;
const MAX_PAGE = 400;

export default async function Similar({
  params,
  searchParams,
}: {
  params: Promise<{ uid: string }>;
  searchParams: Promise<{ page?: string }>;
}) {
  const { uid } = await params;
  const e = getEntry(uid);
  if (!e) notFound();
  const sp = await searchParams;
  const page = Math.min(Math.max(Math.floor(Number(sp.page)) || 1, 1), MAX_PAGE);
  const rows = listSimilar(e.uid, { offset: (page - 1) * PAGE, limit: PAGE + 1 });
  const more = rows.length > PAGE && page < MAX_PAGE;
  const shown = rows.slice(0, PAGE);
  const href = (p: number) => `/similar/${e.uid}` + (p > 1 ? `?page=${p}` : "");

  return (
    <main>
      <h1>Similar entries</h1>
      <p className="lede">
        Entries that say much the same thing as this one, best ranked first. Each is its own
        sealed record with its own time and author.
      </p>
      <EntryCard e={e} />
      <h2 style={{ fontSize: "1.1rem" }}>
        {e.similar === 1 ? "1 similar entry" : `${e.similar.toLocaleString("en")} similar entries`}
      </h2>
      {shown.length === 0 ? (
        <p className="empty">
          {page > 1 ? <Link href={href(1)}>Nothing on this page. Back to the start.</Link> : "None yet."}
        </p>
      ) : (
        shown.map((x) => <EntryCard key={x.uid} e={x} />)
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

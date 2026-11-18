import { headers } from "next/headers";
import Link from "next/link";
import EntryCard from "@/components/EntryCard";
import { rateLimitedHeaders } from "@/lib/http";
import { countEntries, listEntries, type Sort, type Status } from "@/lib/entries";

export type RecordParams = {
  status?: string;
  before?: string;
  page?: string;
  q?: string;
  from?: string;
  to?: string;
};

const BASE: Record<Sort, string> = { top: "/", new: "/new" };

const TABS: { key: "all" | Status; label: string }[] = [
  { key: "all", label: "All" },
  { key: "revealed", label: "Revealed" },
  { key: "anonymous", label: "Anonymous" },
  { key: "unknown", label: "Unknown" },
];

/** The record, ranked by likes ("top", the landing page) or newest first ("new"). */
export default async function RecordView({ sp, sort }: { sp: RecordParams; sort: Sort }) {
  const status =
    sp.status === "revealed" || sp.status === "anonymous" || sp.status === "unknown"
      ? (sp.status as Status)
      : undefined;
  const before = sort === "new" ? Number(sp.before) || undefined : undefined;
  const page = sort === "top" ? Math.min(Math.max(Math.floor(Number(sp.page)) || 1, 1), 400) : 1;
  const q = sp.q?.trim().slice(0, 100) || undefined;
  const day = (s?: string) => (s && /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : undefined);
  const from = day(sp.from);
  const to = day(sp.to);
  const PAGE = 25;
  // Searching scans the whole table, so it is rate limited per caller.
  const searching = Boolean(q || from || to);
  if (searching && rateLimitedHeaders(await headers(), "search", 30, 60_000)) {
    return (
      <main>
        <h1>{sort === "top" ? "Popular posts" : "Latest posts"}</h1>
        <p className="empty">Too many searches. Wait a moment and try again.</p>
      </main>
    );
  }
  const entries = listEntries({
    status,
    sort,
    offset: (page - 1) * PAGE,
    limit: PAGE + 1,
    beforeSeq: before,
    q,
    from,
    to,
  });
  const counts = countEntries({ q, from, to });
  const more = entries.length > PAGE;
  const shown = entries.slice(0, PAGE);
  const filtered = Boolean(q || from || to);

  const href = (extra: Record<string, string | undefined>, base = BASE[sort]) => {
    const p = new URLSearchParams();
    const merged = { status, q, from, to, ...extra };
    for (const [k, v] of Object.entries(merged)) if (v) p.set(k, v);
    const s = p.toString();
    return base + (s ? "?" + s : "");
  };

  return (
    <main>
      <h1>{sort === "top" ? "Popular posts" : "Latest posts"}</h1>
      <p className="lede">
        What people said, and when. Names stay hidden until the author reveals them. Anyone can
        read this, no account needed.
      </p>

      <nav className="tabs" aria-label="Order">
        <Link href={href({}, BASE.top)} aria-current={sort === "top" ? "page" : undefined}>
          Popular
        </Link>
        <Link href={href({}, BASE.new)} aria-current={sort === "new" ? "page" : undefined}>
          Latest
        </Link>
      </nav>
      <p className="count" style={{ marginTop: 0 }}>
        {sort === "top"
          ? "Most liked first, with newer posts given a head start. Dislikes push a post down. Posts that say much the same thing are shown once, by the best ranked of them."
          : "Newest first, in the order they were posted."}
      </p>

      <form action={BASE[sort]} method="get" role="search" className="row" style={{ marginTop: 0, flexWrap: "wrap" }}>
        {status ? <input type="hidden" name="status" value={status} /> : null}
        <input
          type="text"
          name="q"
          defaultValue={q ?? ""}
          placeholder="Search what was said"
          aria-label="Search what was said"
          maxLength={100}
        />
        <button type="submit">Search</button>
        <div className="row" style={{ flexBasis: "100%", marginTop: 0, alignItems: "center" }}>
          <label className="meta">
            Sealed from{" "}
            <input type="date" name="from" defaultValue={from ?? ""} max={to ?? undefined} />
          </label>
          <label className="meta">
            to <input type="date" name="to" defaultValue={to ?? ""} min={from ?? undefined} />
          </label>
          <span className="meta">(dates are UTC)</span>
        </div>
      </form>

      <nav className="tabs" aria-label="Filter">
        {TABS.map((t) => {
          const active = (status ?? "all") === t.key;
          return (
            <Link
              key={t.key}
              href={href({ status: t.key === "all" ? undefined : t.key })}
              aria-current={active ? "page" : undefined}
            >
              {t.label} ({counts[t.key]})
            </Link>
          );
        })}
      </nav>
      {filtered ? (
        <p className="count">
          Showing
          {q ? <> results for “{q}”</> : " everything"}
          {from && to ? <> sealed {from} to {to}</> : from ? <> sealed on or after {from}</> : to ? <> sealed on or before {to}</> : null}
          . <Link href={href({ q: undefined, from: undefined, to: undefined })}>Clear</Link>
        </p>
      ) : null}

      {shown.length === 0 ? (
        <p className="empty">{filtered ? "Nothing matches that search." : "Nothing here yet."}</p>
      ) : (
        shown.map((e) => <EntryCard key={e.uid} e={e} />)
      )}

      {more || page > 1 ? (
        <div className="row" style={{ justifyContent: "center" }}>
          {sort === "top" && page > 1 ? (
            <Link className="btn" href={href({ page: page > 2 ? String(page - 1) : undefined })}>
              Previous
            </Link>
          ) : null}
          {more ? (
            <Link
              className="btn"
              href={href(
                sort === "top"
                  ? { page: String(page + 1) }
                  : { before: String(shown[shown.length - 1].seq) },
              )}
            >
              {sort === "top" ? "Next" : "Older"}
            </Link>
          ) : null}
        </div>
      ) : null}
    </main>
  );
}

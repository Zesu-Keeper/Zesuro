import fs from "node:fs";
import path from "node:path";
import { parse, type Block, type Inline } from "@/lib/mini-md";

export type DocGroup = { name: string; sections: string[] };
export type StartCard = { href: string; title: string; text: string };

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

type Topic = { title: string | null; blocks: Block[] };
type Category = { title: string; topics: Topic[] };

function categorise(blocks: Block[]): { title: string; lede: Block[]; cats: Category[] } {
  let title = "Help";
  const lede: Block[] = [];
  const cats: Category[] = [];
  let cat: Category | null = null;
  let topic: Topic | null = null;
  for (const b of blocks) {
    if (b.k === "h1") { title = b.text; continue; }
    if (b.k === "h2") { cat = { title: b.text, topics: [] }; cats.push(cat); topic = null; continue; }
    if (!cat) { lede.push(b); continue; }
    if (b.k === "h3") { topic = { title: b.text, blocks: [] }; cat.topics.push(topic); continue; }
    if (!topic) { topic = { title: null, blocks: [] }; cat.topics.push(topic); }
    topic.blocks.push(b);
  }
  return { title, lede, cats };
}

function Inl({ a }: { a: Inline[] }) {
  return (
    <>
      {a.map((x, i) =>
        x.t === "code" ? <code key={i} className="mono">{x.v}</code>
        : x.t === "bold" ? <strong key={i}>{x.v}</strong>
        : x.t === "link" ? <a key={i} href={x.href} {...(x.href.startsWith("http") ? { rel: "noopener noreferrer" } : {})}>{x.v}</a>
        : <span key={i}>{x.v}</span>)}
    </>
  );
}

function Blocks({ blocks }: { blocks: Block[] }) {
  return (
    <>
      {blocks.map((b, i) => {
        switch (b.k) {
          case "p": return <p key={i}><Inl a={b.inl} /></p>;
          case "ul": return <ul key={i}>{b.items.map((it, j) => <li key={j}><Inl a={it} /></li>)}</ul>;
          case "ol": return <ol key={i}>{b.items.map((it, j) => <li key={j}><Inl a={it} /></li>)}</ol>;
          case "code": return <pre key={i} className="mono"><code>{b.text}</code></pre>;
          case "table": return (
            <table key={i}>
              <thead><tr>{b.head.map((c, j) => <th key={j}><Inl a={c} /></th>)}</tr></thead>
              <tbody>{b.rows.map((r, j) => <tr key={j}>{r.map((c, k) => <td key={k}><Inl a={c} /></td>)}</tr>)}</tbody>
            </table>
          );
          default: return null;
        }
      })}
    </>
  );
}

/** Renders a Markdown file from docs/ as a grouped help page with a section list and topic cards. */
export default function DocView({ file, groups: defs, start }: { file: string; groups: DocGroup[]; start: StartCard[] }) {
  let src = "";
  try {
    src = fs.readFileSync(path.join(process.cwd(), "docs", file), "utf8");
  } catch {
    return <main><h1>Help</h1><p className="empty">The help file is missing from this install.</p></main>;
  }
  const { title, lede, cats } = categorise(parse(src));
  const byTitle = new Map(cats.map((c) => [c.title, c]));
  const listed = new Set(defs.flatMap((g) => g.sections));
  const groups = [
    ...defs.map((g) => ({ name: g.name, cats: g.sections.map((s) => byTitle.get(s)).filter((c): c is Category => !!c) })),
    { name: "More", cats: cats.filter((c) => !listed.has(c.title)) },
  ].filter((g) => g.cats.length);

  return (
    <main>
      <div className="help-hero">
        <h1>{title}</h1>
        <div className="lede"><Blocks blocks={lede.slice(0, 1)} /></div>
        <Blocks blocks={lede.slice(1)} />
        <div className="help-start">
          {start.map((c) => (
            <a key={c.href} href={c.href}><strong>{c.title}</strong><span>{c.text}</span></a>
          ))}
        </div>
      </div>
      <div className="help-layout">
        <nav className="help-nav" aria-label="Sections">
          {groups.map((g) => (
            <div className="grp" key={g.name}>
              <div>{g.name}</div>
              {g.cats.map((c) => (
                <div key={c.title}>
                  <a href={`#${slug(c.title)}`}>{c.title}</a>
                  <div className="sub">
                    {c.topics.filter((t) => t.title).map((t) => <a key={t.title} href={`#${slug(t.title as string)}`}>{t.title}</a>)}
                  </div>
                </div>
              ))}
            </div>
          ))}
        </nav>
        <div className="help-body">
          {groups.map((g) => g.cats.map((c) => (
            <section className="help-cat" id={slug(c.title)} key={c.title}>
              <p className="eyebrow">{g.name}</p>
              <h2>{c.title}</h2>
              {c.topics.map((t, i) =>
                t.title ? (
                  <div className="help-topic" id={slug(t.title)} key={i}>
                    <h3>{t.title}</h3>
                    <Blocks blocks={t.blocks} />
                  </div>
                ) : (
                  <div className="help-intro" key={i}><Blocks blocks={t.blocks} /></div>
                ),
              )}
            </section>
          )))}
        </div>
      </div>
    </main>
  );
}

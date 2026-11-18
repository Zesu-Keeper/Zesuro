import fs from "node:fs";
import path from "node:path";
import type { Metadata } from "next";
import { parse, type Inline } from "@/lib/mini-md";

export const dynamic = "force-dynamic";
export const metadata: Metadata = {
  title: "Help · Zesuro",
  description: "How to use Zesuro, what protects you, how to host a server and keep the record alive.",
};

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

function Inl({ a }: { a: Inline[] }) {
  return (
    <>
      {a.map((x, i) => (x.t === "code" ? <code key={i} className="mono">{x.v}</code> : x.t === "bold" ? <strong key={i}>{x.v}</strong> : <span key={i}>{x.v}</span>))}
    </>
  );
}

export default function HelpPage() {
  let src = "";
  try {
    src = fs.readFileSync(path.join(process.cwd(), "docs", "HELP.md"), "utf8");
  } catch {
    return <main><h1>Help</h1><p className="empty">The help file is missing from this install.</p></main>;
  }
  const blocks = parse(src);
  const toc = blocks.flatMap((b) => (b.k === "h2" ? [b.text] : []));
  return (
    <main>
      {blocks.map((b, i) => {
        switch (b.k) {
          case "h1": return <h1 key={i}>{b.text}</h1>;
          case "h2": return <h2 key={i} id={slug(b.text)}>{b.text}</h2>;
          case "h3": return <h3 key={i} id={slug(b.text)}>{b.text}</h3>;
          case "p": return <p key={i}>{i === 1 ? <span className="lede"><Inl a={b.inl} /></span> : <Inl a={b.inl} />}{i === 1 ? <nav aria-label="Sections" className="meta">{toc.map((t) => <a key={t} href={`#${slug(t)}`} style={{ marginRight: 14 }}>{t}</a>)}</nav> : null}</p>;
          case "ul": return <ul key={i}>{b.items.map((it, j) => <li key={j}><Inl a={it} /></li>)}</ul>;
          case "ol": return <ol key={i}>{b.items.map((it, j) => <li key={j}><Inl a={it} /></li>)}</ol>;
          case "code": return <pre key={i} className="mono" style={{ overflowX: "auto", whiteSpace: "pre" }}>{b.text}</pre>;
          case "table": return (
            <table key={i}><thead><tr>{b.head.map((c, j) => <th key={j} style={{ textAlign: "left" }}><Inl a={c} /></th>)}</tr></thead>
              <tbody>{b.rows.map((r, j) => <tr key={j}>{r.map((c, k) => <td key={k}><Inl a={c} /></td>)}</tr>)}</tbody></table>
          );
        }
      })}
    </main>
  );
}

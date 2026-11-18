/**
 * A tiny, safe Markdown reader for docs/HELP.md. It understands only what that file uses:
 * "##" and "###" headings, paragraphs, "-" and "1." lists, fenced code, pipe tables and `inline code`
 * and **bold**. It returns data, never HTML, so React escapes everything.
 */
export type Inline = { t: "text" | "code" | "bold"; v: string };
export type Block =
  | { k: "h2" | "h3" | "h1"; text: string }
  | { k: "p"; inl: Inline[] }
  | { k: "ul" | "ol"; items: Inline[][] }
  | { k: "code"; text: string }
  | { k: "table"; head: Inline[][]; rows: Inline[][][] };

export function inline(s: string): Inline[] {
  const out: Inline[] = [];
  const re = /`([^`]+)`|\*\*([^*]+)\*\*/g;
  let i = 0, m: RegExpExecArray | null;
  while ((m = re.exec(s))) {
    if (m.index > i) out.push({ t: "text", v: s.slice(i, m.index) });
    out.push(m[1] !== undefined ? { t: "code", v: m[1] } : { t: "bold", v: m[2] });
    i = m.index + m[0].length;
  }
  if (i < s.length) out.push({ t: "text", v: s.slice(i) });
  return out;
}

const cells = (l: string) => l.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());

export function parse(src: string): Block[] {
  const lines = src.replace(/\r/g, "").split("\n");
  const out: Block[] = [];
  let i = 0;
  while (i < lines.length) {
    const l = lines[i];
    if (!l.trim()) { i++; continue; }
    if (l.startsWith("```")) {
      const buf: string[] = []; i++;
      while (i < lines.length && !lines[i].startsWith("```")) buf.push(lines[i++]);
      i++; out.push({ k: "code", text: buf.join("\n") }); continue;
    }
    const h = /^(#{1,3}) (.*)$/.exec(l);
    if (h) { out.push({ k: (["h1", "h2", "h3"] as const)[h[1].length - 1], text: h[2] }); i++; continue; }
    if (l.startsWith("|")) {
      const rows: string[][] = [];
      while (i < lines.length && lines[i].startsWith("|")) rows.push(cells(lines[i++]));
      const body = rows.filter((r) => !r.every((c) => /^:?-{2,}:?$/.test(c)));
      out.push({ k: "table", head: body[0].map(inline), rows: body.slice(1).map((r) => r.map(inline)) }); continue;
    }
    const ul = /^- /.test(l), ol = /^\d+\. /.test(l);
    if (ul || ol) {
      const items: Inline[][] = [];
      while (i < lines.length && (ul ? /^- /.test(lines[i]) : /^\d+\. /.test(lines[i]))) items.push(inline(lines[i++].replace(ul ? /^- / : /^\d+\. /, "")));
      out.push({ k: ul ? "ul" : "ol", items }); continue;
    }
    const buf: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^(#{1,3} |```|\||- |\d+\. )/.test(lines[i])) buf.push(lines[i++]);
    out.push({ k: "p", inl: inline(buf.join(" ")) });
  }
  return out;
}

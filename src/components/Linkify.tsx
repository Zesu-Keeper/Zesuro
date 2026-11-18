import type { ReactNode } from "react";

const URL_RE = /https?:\/\/[^\s<>"']+/gi;
const TRAILING = /[.,;:!?)\]}]+$/;

/** Turns http(s) links in plain text into anchors. Everything else stays text. */
export default function Linkify({ text, active = true }: { text: string; active?: boolean }) {
  // Inactive: addresses stay readable but aren't links, so there's nothing for spam to gain.
  if (!active) return <>{text}</>;
  const out: ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(URL_RE)) {
    const start = m.index ?? 0;
    const url = m[0].replace(TRAILING, "");
    if (start > last) out.push(text.slice(last, start));
    out.push(
      <a key={start} href={url} target="_blank" rel="noopener noreferrer nofollow ugc">
        {url}
      </a>,
    );
    last = start + url.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return <>{out}</>;
}

import Link from "next/link";
import type { PublicEntry } from "@/lib/entries";
import { LINKS_AT } from "@/lib/limits";
import RedactedText from "./RedactedText";
import ReportButton from "./ReportButton";
import ShareButton from "./ShareButton";
import Stamp from "./Stamp";
import Votes from "./Votes";

const LABEL = { anonymous: "Anonymous", revealed: "Revealed", unknown: "Unknown" } as const;

export default function EntryCard({ e, link = true }: { e: PublicEntry; link?: boolean }) {
  return (
    <article className="card">
      <h2 className="title">
        {link ? <Link href={`/e/${e.uid}`}>{e.title || "Untitled"}</Link> : e.title || "Untitled"}
      </h2>
      <p className="text">
        <RedactedText text={e.text} parts={e.parts} links={e.likes - e.dislikes >= LINKS_AT} />
      </p>
      {e.place ? (
        <p className="place">
          <a
            href={`https://www.openstreetmap.org/?mlat=${e.place.lat}&mlon=${e.place.lng}#map=15/${e.place.lat}/${e.place.lng}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            {e.place.label || `${e.place.lat}, ${e.place.lng}`}
          </a>
        </p>
      ) : e.placeHidden ? (
        <p className="place muted">Place hidden until released</p>
      ) : null}
      <div className="meta">
        <span className={`badge ${e.status}`}>{LABEL[e.status]}</span>
        {e.status === "revealed" && e.handle ? (
          <span>
            said by <span className="who">{e.handle}</span>
          </span>
        ) : null}
        <span>
          Sealed <Stamp ms={e.createdAt} />
        </span>
        {e.status === "revealed" && e.revealedAt ? (
          <span>
            Revealed <Stamp ms={e.revealedAt} />
          </span>
        ) : null}
        {e.status === "anonymous" && e.mode !== "manual" ? (
          e.revealAt ? (
            <span>
              {e.mode === "locked" ? "Locked to reveal " : "Scheduled to reveal "}
              <Stamp ms={e.revealAt} />
            </span>
          ) : (
            <span>
              {e.mode === "locked" ? "Locked to reveal" : "Scheduled to reveal"} (date not shown)
            </span>
          )
        ) : null}
        {e.status === "unknown" && e.deadlineAt ? (
          <span>
            Deadline passed <Stamp ms={e.deadlineAt} />
          </span>
        ) : null}
        {link ? (
          <Link href={`/e/${e.uid}`} aria-label={`Open entry ${e.seq}`}>
            #{e.seq}
          </Link>
        ) : (
          <span>#{e.seq}</span>
        )}
      </div>
      <div className="actions">
        <Votes uid={e.uid} up={e.likes} down={e.dislikes} />
        <ShareButton uid={e.uid} title={e.title} />
        {link ? (
          <Link className="count" href={`/e/${e.uid}#comments`}>
            {e.commentCount === 1 ? "1 comment" : `${e.commentCount.toLocaleString("en")} comments`}
          </Link>
        ) : null}
        {e.similar > 0 ? (
          <Link className="count" href={`/similar/${e.uid}`}>
            {e.similar === 1 ? "1 similar entry" : `${e.similar.toLocaleString("en")} similar entries`}
          </Link>
        ) : null}
        <ReportButton kind="entry" id={e.uid} count={e.reports} />
      </div>
      {e.status === "revealed" ? (
        <div className="actions">
          <Votes kind="outcome" uid={e.uid} up={e.happened} down={e.notHappened} />
        </div>
      ) : null}
    </article>
  );
}

import { contentString } from "@/lib/commit";
import { sha256Hex } from "@/lib/opening";
import { notFound } from "next/navigation";
import EntryCard from "@/components/EntryCard";
import PlaceMap from "@/components/PlaceMap";
import Comments from "@/components/Comments";
import ShareButton from "@/components/ShareButton";
import { listComments } from "@/lib/comments";
import Link from "next/link";
import { getEntry, listSimilar } from "@/lib/entries";
import { REDACTION_MARK } from "@/lib/secret";

export const dynamic = "force-dynamic";

export async function generateMetadata({ params }: { params: Promise<{ uid: string }> }) {
  const { uid } = await params;
  const e = getEntry(uid);
  if (!e) return { title: "Not found · Zesuro" };
  const title = `${e.title || `Entry #${e.seq}`} · Zesuro`;
  // What a shared link previews as. Redacted passages stay hidden here too.
  const words = e.text.replaceAll(REDACTION_MARK, "▇▇▇").replace(/\s+/g, " ").trim();
  const who = e.status === "revealed" && e.handle ? `Said by ${e.handle}. ` : "Author not revealed yet. ";
  const description = who + (words.length > 160 ? words.slice(0, 157) + "…" : words);
  return {
    title,
    description,
    openGraph: { title, description, type: "article" },
    twitter: { card: "summary", title, description },
  };
}

export default async function EntryPage({ params }: { params: Promise<{ uid: string }> }) {
  const { uid } = await params;
  const e = getEntry(uid);
  if (!e) notFound();
  const first = listComments(e.uid);
  const similar = e.similar > 0 ? listSimilar(e.uid, { limit: 3 }) : [];

  return (
    <main>
      {e.delisted ? (
        <div className="warnbox">
          The site operator has taken this entry off the lists. It is still
          part of the record and can be opened with its link.
        </div>
      ) : null}
      <EntryCard e={e} link={false} />
      <p className="count" style={{ marginTop: -4 }}>
        Link to this entry: <span className="mono">/e/{e.uid}</span>{" "}
        <ShareButton uid={e.uid} title={e.title} />
      </p>
      {e.place ? <PlaceMap pin={{ lat: e.place.lat, lng: e.place.lng }} height={260} /> : null}

      {similar.length > 0 ? (
        <section aria-label="Similar entries">
          <h2 style={{ fontSize: "1.1rem" }}>
            Similar entries <span className="count">(best ranked first)</span>
          </h2>
          {similar.map((x) => (
            <EntryCard key={x.uid} e={x} />
          ))}
          {e.similar > similar.length ? (
            <p className="count">
              <Link href={`/similar/${e.uid}`}>See all {e.similar.toLocaleString("en")} similar entries</Link>
            </p>
          ) : null}
        </section>
      ) : null}

      <Comments
        entry={{
          uid: e.uid,
          nonce: e.nonce,
          commitment: e.commitment,
          commitV: e.commitV,
          title: e.title,
          text: e.text,
          placeMode: e.placeMode,
          place: e.place,
          secretCommit: e.secretCommit,
          mode: e.mode,
        }}
        initial={first.comments.map((c) => ({
          id: c.id,
          uid: c.uid,
          text: c.text,
          tag: c.tag,
          createdAt: c.createdAt,
          textHash: c.textHash,
          reports: c.reports,
          removed: c.removed,
        }))}
        initialMore={first.more}
      />

      <h1 style={{ fontSize: "1.1rem" }}>How this is kept safe</h1>
      <div className="card">
        <p className="lede" style={{ marginBottom: 8 }}>
          This is post number {e.seq}. Each post is linked to the one before it, so its words and
          the time it was posted can&apos;t be changed without breaking every post after it.
        </p>
        <details>
          <summary>Technical details, for people who want to check</summary>
        <p className="mono">entry hash: {e.entryHash}</p>
        <p className="mono">previous hash: {e.prevHash}</p>
        <p className="mono">author commitment: {e.commitment}</p>
        {e.schedCommit ? (
          <p className="mono">schedule commitment: {e.schedCommit}</p>
        ) : null}
        {e.timelock ? (
          <>
            <p className="mono">time-lock hash: {e.timelock.hash}</p>
            <p className="meta">
              {e.status === "revealed"
                ? "The author's name and any hidden parts were locked in their browser until a public timer (the drand beacon) reached the reveal time. "
                : "The author's name and any hidden parts are locked in their browser. Nobody, including this site, can read them before the reveal time. "}
              The hash above is part of the chain
              {e.timelock.round !== null ? `, and the lock opens at drand round ${e.timelock.round}` : ""}.
            </p>
          </>
        ) : null}
        {e.secretCommit ? (
          <p className="mono">hidden-parts commitment: {e.secretCommit}</p>
        ) : null}
        {e.secret ? (
          <p className="mono">
            hidden parts: {JSON.stringify([e.secret.parts, e.secret.place, e.secret.salt])}{" "}
            (SHA-256 of this equals the hidden-parts commitment)
          </p>
        ) : e.secretCommit ? (
          <p className="meta">
            The hidden words{e.placeHidden ? " and the place" : ""} are locked in above. They will
            be shown here when the post is revealed.
          </p>
        ) : null}
        {e.schedule ? (
          <p className="mono">
            schedule: {JSON.stringify([e.schedule.revealAt, e.schedule.deadlineAt, e.schedule.salt])}{" "}
            (SHA-256 of this equals the schedule commitment)
          </p>
        ) : e.schedCommit ? (
          <p className="meta">
            The reveal date is locked in above. The author chose not to show it yet. It will be
            shown here once it is no longer private.
          </p>
        ) : null}
        </details>
        <p className="meta">
          This site stamps the whole record every few minutes, and other people&apos;s copies of it
          (mirrors) check and sign each stamp. See <Link href="/anchors">Anchors</Link>. Until a
          mirror has signed a stamp made after this post, the time shown is only this site&apos;s word.
        </p>
      </div>

      {e.status === "revealed" && e.opening ? (
        <details className="card">
          <summary>Check that the author really wrote this</summary>
          {e.opening.v === 2 ? (
            <>
              <p className="meta">
                This post was sealed with a key made just for it, and its lock covers the exact words,
                so it can only match this text. Anyone can check:
                SHA-256 of{" "}
                <span className="mono">
                  zesuro:commit:v2:&lt;public key&gt;:&lt;salt&gt;:&lt;SHA-256 of the content&gt;
                </span>{" "}
                equals the commitment above, and the signature below, made with that key (Ed25519),
                covers{" "}
                <span className="mono">
                  whenisaid:reveal:v2:{e.uid}:{e.opening.handle}
                </span>
                .
              </p>
              <p className="mono">content: {contentString(e)}</p>
              <p className="mono">content SHA-256: {sha256Hex(contentString(e))}</p>
            </>
          ) : (
            <p className="meta">
              This entry was sealed before commitments covered content. The author proved they
              hold the key behind the commitment above: SHA-256 of the public key and salt below
              equals it, and the signature covers{" "}
              <span className="mono">
                whenisaid:reveal:v1:{e.uid}:{e.opening.handle}
              </span>
              . Nothing ties the commitment to this text except the site&apos;s own record.
            </p>
          )}
          <p className="mono">public key: {JSON.stringify(e.opening.pub)}</p>
          <p className="mono">salt: {e.opening.salt}</p>
          <p className="mono">signature: {e.opening.sig}</p>
        </details>
      ) : null}
    </main>
  );
}

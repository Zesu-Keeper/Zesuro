import type { Metadata } from "next";
import Stamp from "@/components/Stamp";
import { anchorPublicKey, listAnchors } from "@/lib/anchors";

export const dynamic = "force-dynamic";
export const metadata: Metadata = {
  title: "Anchors · Zesuro",
  description: "Signed tips of the record, countersigned by independent mirrors.",
};

export default function AnchorsPage() {
  const anchors = listAnchors(0, 50);
  const key = anchorPublicKey();
  return (
    <main>
      <h1>Anchors</h1>
      <p className="lede">
        Every few minutes this site signs the tip of its record: the hash that every entry and
        comment feeds into. Mirrors run by other people keep their own complete copy of the record,
        check each signed tip against it and countersign it with the time they saw it. A mirror
        refuses to sign if anything it already holds has been changed. So once a tip is witnessed,
        no entry before it can be altered, removed or backdated without the witnesses&apos; own
        copies and signatures showing it.
      </p>
      <p className="meta">
        Anyone can check all of this without trusting this site, or run a mirror. Both are single
        files that need only Node: <span className="mono">scripts/verify-log.mjs</span> and{" "}
        <span className="mono">scripts/mirror.mjs</span> in the project.
      </p>
      {key ? <p className="mono">site signing key: {key}</p> : null}
      {anchors.length === 0 ? <p className="empty">No anchors yet.</p> : null}
      {anchors.map((a) => (
        <div className="card" key={a.id}>
          <div className="meta" style={{ marginTop: 0 }}>
            <span>#{a.id}</span>
            <Stamp ms={a.at} />
            <span>
              {a.head.entries.count} entries · {a.head.comments.count} comments
            </span>
            <a href={`/api/anchors/${a.id}/head`}>signed text</a>
          </div>
          <p className="mono">entries tip: {a.head.entries.tip}</p>
          <p className="mono">comments tip: {a.head.comments.tip}</p>
          {a.witnesses.length === 0 ? (
            <p className="meta">Not witnessed yet. Until it is, this is only this site&apos;s word.</p>
          ) : (
            a.witnesses.map((w) => (
              <p className="meta" key={w.key}>
                Witnessed by <b>{w.name}</b> <Stamp ms={w.at} />{" "}
                <span className="mono">{w.key}</span>
              </p>
            ))
          )}
        </div>
      ))}
    </main>
  );
}

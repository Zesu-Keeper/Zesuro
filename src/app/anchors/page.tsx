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
        Every few minutes this site puts a signed stamp on its whole record, like a seal on an
        envelope. Other people run copies of the site, called mirrors. They keep their own copy of
        the record, check it against each stamp, and add their own signature with the time they saw
        it. A mirror refuses to sign if anything it already had has been changed. So once a stamp has
        been countersigned, nothing before it can be changed, removed or backdated without the
        mirrors&apos; copies showing it.
      </p>
      <p className="meta">
        You don&apos;t have to take our word for any of this. People who are comfortable with a command line can check it
        themselves, or run a mirror. The two tools are{" "}
        <span className="mono">scripts/verify-log.mjs</span> and <span className="mono">scripts/mirror.mjs</span> in the project.
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
            <p className="meta">No mirror has signed this one yet. Until one does, it is only this site&apos;s word.</p>
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

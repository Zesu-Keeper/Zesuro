import type { Metadata } from "next";
import Link from "next/link";
import Stamp from "@/components/Stamp";
import { anchorPublicKey, listAnchors } from "@/lib/anchors";

export const dynamic = "force-dynamic";
export const metadata: Metadata = {
  title: "Anchors · Zesuro",
  description: "Proof that the record has not been changed, checked by other sites.",
};

export default function AnchorsPage() {
  const anchors = listAnchors(0, 50);
  const key = anchorPublicKey();
  return (
    <main>
      <h1>Anchors</h1>
      <p className="lede">
        Every few minutes this site puts a signed stamp on its whole record. Other sites, called
        mirrors, keep their own copy and check each stamp. If anything had been changed, the copies
        would no longer match. <Link href="/help#mirrors">How mirrors work</Link>
      </p>
      <p className="meta">
        You don&apos;t have to take our word for it. The{" "}
        <Link href="/help/technical#verifying-the-record">technical guide</Link> shows how to check the record yourself.
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

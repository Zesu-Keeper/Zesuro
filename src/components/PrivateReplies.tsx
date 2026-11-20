"use client";

import { useEffect, useState } from "react";
import { loadMine, updateMine, type MineEntry } from "@/lib/client-crypto";
import { fetchInbox } from "@/lib/inbox-client";
import { newsroomLists, verifyReplySig } from "@/lib/journalist";
import { expireSecrets, openReply, parseReplyBody, type ReplyBody } from "@/lib/mailbox";

interface Reply {
  id: number;
  at: number;
  uid: string;
  title: string;
  body: ReplyBody;
  verified: boolean;
}

/** Private replies to my posts. Opened here, in this browser, and never stored. */
export default function PrivateReplies({ createdAt }: { createdAt: Record<string, number> }) {
  const [replies, setReplies] = useState<Reply[] | null>(null);
  // The parent builds a new object on every render; only a real change should fetch again.
  const key = JSON.stringify(createdAt);

  useEffect(() => {
    const createdAt = JSON.parse(key) as Record<string, number>;
    let off = false;
    (async () => {
      const now = Date.now();
      const mine = loadMine().filter((m) => m.mailbox && !m.pendingBy);
      // Throw away the keys of months that are over: replies from those months can then never be opened.
      for (const m of mine) {
        const sealedAt = createdAt[m.uid] ?? m.createdAt;
        const kept = expireSecrets(m.mailbox!.secrets, sealedAt, now);
        if (JSON.stringify(kept) !== JSON.stringify(m.mailbox!.secrets)) updateMine(m.uid, { mailbox: { ...m.mailbox!, secrets: kept } });
        m.mailbox!.secrets = kept;
      }
      const byUid = new Map<string, MineEntry>(mine.map((m) => [m.uid, m]));
      const out: Reply[] = [];
      for (const msg of await fetchInbox()) {
        const m = byUid.get(msg.uid);
        if (!m) continue;
        const opened = openReply(msg.uid, m.mailbox!.secrets, msg.blob);
        const body = opened && parseReplyBody(opened.plain);
        if (!body) continue;
        let verified = false;
        if (body.from && (await verifyReplySig(body.from, msg.uid, body.invite, body.text)))
          verified = await newsroomLists(body.from.domain, body.from.key, body.from.name);
        out.push({ id: msg.id, at: msg.at, uid: msg.uid, title: m.title || m.text.slice(0, 60), body, verified });
      }
      if (!off) setReplies(out);
    })();
    return () => {
      off = true;
    };
  }, [key]);

  if (!replies || !replies.length) return null;
  const answer = (r: Reply) => {
    try {
      sessionStorage.setItem("zesuro.join.reply", JSON.stringify({ uid: r.uid, title: r.title }));
    } catch {
      /* the chat still opens; it just isn't labelled */
    }
    window.location.href = `/chat#i=${r.body.invite}`;
  };
  const verified = replies.filter((r) => r.verified);
  const other = replies.filter((r) => !r.verified);
  const show = (r: Reply) => (
    <div className="card" key={r.id}>
      <p className="meta" style={{ marginTop: 0 }}>
        {r.verified ? (
          <span className="badge revealed">Verified: {r.body.from!.name} at {r.body.from!.domain}</span>
        ) : (
          <span className="badge unknown">Not verified</span>
        )}{" "}
        Reply to &ldquo;{r.title}&rdquo;
      </p>
      <p className="text">{r.body.text}</p>
      <button type="button" className="primary" onClick={() => answer(r)}>Answer in a private chat</button>
    </div>
  );
  return (
    <section aria-label="Private replies">
      <h2 style={{ fontSize: "1.1rem" }}>Private replies</h2>
      <p className="count">
        Only you can read these. Answering opens a private chat that is kept only until you close the tab. Don&apos;t send
        your name or anything that identifies you until you&apos;re sure who you&apos;re talking to.
      </p>
      {verified.map(show)}
      {other.length ? (
        <details>
          <summary>
            {other.length} not verified: could be anyone, including the people you wrote about
          </summary>
          {other.map(show)}
        </details>
      ) : null}
    </section>
  );
}

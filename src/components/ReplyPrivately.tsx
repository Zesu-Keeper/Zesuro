"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { inviteFragment, newInvite } from "@/lib/chat-crypto";
import { addInvite } from "@/lib/chat-store";
import { loadJournalist, signReply, type JournalistId } from "@/lib/journalist";
import { mailboxRootOf, monthIndex, sealReply, type MailboxLeaf } from "@/lib/mailbox";
import { postWithTicket, warmTicket } from "@/lib/ticket-client";

/**
 * "Reply privately" on a post. The reply is locked to the post's own mailbox key, which only its real author holds,
 * and carries a one-time chat link. If the author answers, the chat appears under Private chat in this browser.
 */
export default function ReplyPrivately({ uid, root, title }: { uid: string; root: string; title: string }) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  const [me, setMe] = useState<JournalistId | null>(null);
  const [sign, setSign] = useState(true);
  const [trap, setTrap] = useState("");
  useEffect(() => {
    setMe(loadJournalist());
  }, []);

  async function send() {
    setErr(null);
    setBusy(true);
    try {
      const r = await fetch(`/api/entries/${uid}/mailbox`, { cache: "no-store" });
      if (!r.ok) throw new Error("This post doesn't take private replies.");
      const mb = (await r.json()) as { root: string; leaves: MailboxLeaf[]; createdAt: number };
      // The keys must be exactly the ones the record holds a fingerprint of.
      if (mb.root !== root || mailboxRootOf(uid, mb.leaves) !== root)
        throw new Error("The private-reply keys for this post don't match the record. Don't send anything.");
      const idx = monthIndex(mb.createdAt, Date.now(), mb.leaves.length);
      if (idx < 0) throw new Error("This post no longer takes private replies: they are open for a year.");
      // A one-time chat link that only the author will ever see.
      const inv = await newInvite(1);
      const res = await postWithTicket("/api/chat/invites", { id: inv.id, owner: inv.ownerHash, hello: inv.hello, maxUses: 1 }, trap);
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || "Could not prepare the reply");
      if (!addInvite({ secret: inv.secret, id: inv.id, ownerSecret: inv.ownerSecret, privs: inv.privs, maxUses: 1, createdAt: Date.now(), reply: { uid, title } }))
        throw new Error("This browser is not letting the site store the chat key. Private windows and blocked storage won't work.");
      const t = text.trim();
      const from = me && sign ? await signReply(me, uid, inv.secret, t) : undefined;
      const blob = sealReply(uid, mb.leaves, idx, JSON.stringify({ v: 1, invite: inv.secret, text: t, ...(from ? { from } : {}) }));
      const sentRes = await postWithTicket(`/api/entries/${uid}/reply`, { blob }, trap);
      if (!sentRes.ok) throw new Error((await sentRes.json().catch(() => ({}))).error || "Could not send the reply");
      void inviteFragment;
      setSent(true);
      setText("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not send the reply");
    } finally {
      setBusy(false);
    }
  }

  if (sent)
    return (
      <div className="notice">
        Sent. Only the author of this post can read it. If they answer, the chat appears under{" "}
        <Link href="/chat">Private chat</Link> in this browser, so keep using this browser.
      </div>
    );
  if (!open)
    return (
      <p>
        <button
          type="button"
          onClick={() => {
            setOpen(true);
            warmTicket();
          }}
        >
          Reply privately
        </button>{" "}
        <span className="count">Only the author can read it, and they stay anonymous.</span>
      </p>
    );
  return (
    <div className="card">
      <h2 className="title">Reply privately to the author</h2>
      <p className="count">
        Only the real author of this post can read this. If they answer, you&apos;ll talk in a private chat. You won&apos;t
        learn who they are, and they won&apos;t learn who you are unless you say.
      </p>
      <input type="text" name="website" className="trap" tabIndex={-1} autoComplete="off" aria-hidden="true" value={trap} onChange={(e) => setTrap(e.target.value)} />
      <textarea className="plain" rows={4} maxLength={2000} value={text} onChange={(e) => setText(e.target.value)} placeholder="Introduce yourself and say why you'd like to talk" aria-label="Your private reply" />
      {me ? (
        <label className="opt">
          <input type="checkbox" checked={sign} onChange={(e) => setSign(e.target.checked)} />
          <b>Sign as {me.name} at {me.domain}</b>
          <small>The author sees &quot;Verified&quot; if your newsroom lists your key. Otherwise your reply shows as not verified.</small>
        </label>
      ) : (
        <p className="count">
          Journalist? <Link href="/journalist">Set up a verified identity</Link> so the author can tell you are who you say.
        </p>
      )}
      {err ? <p className="err">{err}</p> : null}
      <div className="row" style={{ justifyContent: "flex-start" }}>
        <button type="button" className="primary" onClick={send} disabled={busy || !text.trim()}>
          {busy ? "Sending…" : "Send privately"}
        </button>
        <button type="button" className="link" onClick={() => setOpen(false)} disabled={busy}>
          Cancel
        </button>
      </div>
    </div>
  );
}

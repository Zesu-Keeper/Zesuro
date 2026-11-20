"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { loadKey, ownsEntry, type PublicForCommit } from "@/lib/client-crypto";
import {
  authorTag,
  authorThread,
  forgetHeld,
  isAuthorComment,
  linkFragment,
  loadHeld,
  parseFragment,
  randomTag,
  saveHeld,
  threadsSupported,
  type ThreadKey,
} from "@/lib/thread-crypto";
import { postWithTicket, warmTicket } from "@/lib/ticket-client";
import ReportButton from "./ReportButton";
import Stamp from "./Stamp";

export interface CommentView {
  id: number;
  uid: string;
  text: string;
  tag: string;
  createdAt: number;
  /** SHA-256 of the text as posted. Kept even if the text is removed. */
  textHash: string;
  /** How many readers have flagged it as spam. Shown; nothing is hidden for it. */
  reports: number;
  /** Text removed by the site operator. The record of it stays. */
  removed: boolean;
}

const MAX = 2000;
/** Same normalisation as the server, so the author's signature covers exactly what is stored. */
const normalise = (s: string) => s.replace(/\r\n?/g, "\n").trim();

export default function Comments({
  entry,
  initial,
  initialMore,
}: {
  entry: PublicForCommit;
  initial: CommentView[];
  initialMore: boolean;
}) {
  const [list, setList] = useState<CommentView[]>(initial);
  // Paging cursor: the last id loaded from the server in order. New comments posted here are
  // appended to the list but don't move it, so "Show more" never skips anything.
  const cursor = useRef(initial.length ? initial[initial.length - 1].id : 0);
  const [more, setMore] = useState(initialMore);
  const [loading, setLoading] = useState(false);

  const [held, setHeld] = useState<ThreadKey | null>(null);
  const [owner, setOwner] = useState<Awaited<ReturnType<typeof authorThread>> | null>(null);
  const [supported, setSupported] = useState(true);
  const [authorIds, setAuthorIds] = useState<Set<string>>(new Set());
  const checked = useRef<Set<string>>(new Set());

  const [text, setText] = useState("");
  const [asAuthor, setAsAuthor] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [showLink, setShowLink] = useState(false);
  // A field people never see. Scripts that fill in every field give themselves away.
  const [trap, setTrap] = useState("");

  useEffect(() => {
    warmTicket();
  }, []);
  const [copied, setCopied] = useState(false);

  // Pick up a private link from the address, then take it out of the address bar so it isn't
  // left on screen, in screenshots, or in shared copies of the URL.
  useEffect(() => {
    let live = true;
    (async () => {
      const ok = await threadsSupported();
      if (!live) return;
      setSupported(ok);
      const fromUrl = parseFragment(location.hash);
      if (fromUrl) {
        saveHeld(entry.uid, fromUrl);
        history.replaceState(null, "", location.pathname + location.search);
      }
      const h = fromUrl ?? loadHeld(entry.uid);
      if (h) setHeld(h);
      if (!ok) return;
      const k = loadKey();
      if (k && (await ownsEntry(k, entry))) {
        const t = await authorThread(k, entry.nonce);
        if (live) setOwner(t);
      }
    })().catch(() => {});
    return () => {
      live = false;
    };
  }, [entry]);

  // Check each comment once against whichever thread key this browser has.
  const key = owner?.key ?? held;
  useEffect(() => {
    if (!key || !supported) return;
    let live = true;
    (async () => {
      const found: string[] = [];
      for (const c of list) {
        if (checked.current.has(c.uid)) continue;
        checked.current.add(c.uid);
        if (await isAuthorComment(key, entry.uid, c)) found.push(c.uid);
      }
      if (live && found.length)
        setAuthorIds((prev) => new Set([...prev, ...found]));
    })();
    return () => {
      live = false;
    };
  }, [key, supported, list, entry.uid]);

  const loadMore = useCallback(async () => {
    setLoading(true);
    setErr(null);
    try {
      const r = await fetch(`/api/entries/${entry.uid}/comments?after=${cursor.current}`, {
        cache: "no-store",
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || "Could not load comments");
      const page = data.comments as CommentView[];
      if (page.length) cursor.current = page[page.length - 1].id;
      setList((prev) => {
        const seen = new Set(prev.map((c) => c.uid));
        return [...prev, ...page.filter((c) => !seen.has(c.uid))].sort((a, b) => a.id - b.id);
      });
      setMore(Boolean(data.more));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not load comments");
    } finally {
      setLoading(false);
    }
  }, [entry.uid]);

  async function post() {
    const body = normalise(text);
    if (!body) return setErr("Write something first.");
    if (body.length > MAX) return setErr(`Comments can be up to ${MAX.toLocaleString()} characters.`);
    setBusy(true);
    setErr(null);
    try {
      const uid = crypto.randomUUID();
      const tag = asAuthor && owner ? await authorTag(owner, entry.uid, uid, body) : randomTag();
      const r = await postWithTicket(
        `/api/entries/${entry.uid}/comments`,
        { uid, text: body, tag },
        trap,
      );
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || "Could not post");
      const c = data.comment as CommentView;
      setList((prev) => [...prev.filter((x) => x.uid !== c.uid), c].sort((a, b) => a.id - b.id));
      setText("");
      setAsAuthor(false);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not post");
    } finally {
      setBusy(false);
    }
  }

  const privateLink = owner
    ? `${typeof location === "undefined" ? "" : location.origin}/e/${entry.uid}#${linkFragment(owner.key)}`
    : "";

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(privateLink);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      window.prompt("Copy this private link", privateLink);
    }
  }

  return (
    <section id="comments" aria-label="Comments">
      <h2 style={{ fontSize: "1.1rem" }}>
        Comments {list.length ? <span className="count">({list.length}{more ? "+" : ""})</span> : null}
      </h2>

      {owner ? (
        <div className="card">
          <p className="lede" style={{ marginBottom: 8 }}>
            <b>You wrote this post.</b> You can give people you trust a private link. With it, they
            can tell which comments here are yours. Nobody else can, not even this site.
          </p>
          {showLink ? (
            <>
              <input
                type="text"
                readOnly
                value={privateLink}
                aria-label="Private follow-up link"
                onFocus={(e) => e.currentTarget.select()}
              />
              <div className="row">
                <button type="button" onClick={copyLink}>
                  {copied ? "Copied" : "Copy private link"}
                </button>
                <button type="button" className="link" onClick={() => setShowLink(false)}>
                  Hide
                </button>
              </div>
              <div className="warnbox">
                Anyone with this link can tell which comments on this post are yours, so only send
                it to people you trust. You can&apos;t take it back. It doesn&apos;t show your name,
                it doesn&apos;t let anyone post as you, and it doesn&apos;t connect you to your other
                posts. Your key backup includes it.
              </div>
            </>
          ) : (
            <button type="button" onClick={() => setShowLink(true)}>
              Show private link
            </button>
          )}
        </div>
      ) : held ? (
        <div className="card">
          <p className="lede" style={{ marginBottom: 8 }}>
            You have a private link for this post. Comments from the person who gave you the link are
            marked <span className="badge revealed">From the author</span>. Only people with the
            link can see the mark.
          </p>
          <button
            type="button"
            className="link"
            onClick={() => {
              forgetHeld(entry.uid);
              setHeld(null);
              setAuthorIds(new Set());
              checked.current = new Set();
            }}
          >
            Forget this link on this device
          </button>
        </div>
      ) : null}
      {(owner || held) && !supported ? (
        <p className="err">
          This browser can&apos;t check private follow-ups. Update it, or use a current Firefox,
          Chrome or Safari.
        </p>
      ) : null}

      {list.length === 0 ? <p className="empty">No comments yet.</p> : null}
      {list.map((c) => {
        const mine = authorIds.has(c.uid);
        return (
          <article className={`card comment${mine ? " from-source" : ""}`} key={c.uid}>
            <div className="meta" style={{ marginTop: 0 }}>
              {mine ? (
                <span className="badge revealed">{owner ? "You, as the author" : "From the author"}</span>
              ) : (
                <span>Anonymous</span>
              )}
              <Stamp ms={c.createdAt} />
              <span>c{c.id}</span>
              {c.removed ? null : <ReportButton kind="comment" id={String(c.id)} count={c.reports} />}
            </div>
            {c.removed ? (
              <p className="count comment-text">
                Removed by the site owner. A record of it stays: it was posted at the time shown. Its
                fingerprint is <span className="mono">{c.textHash.slice(0, 16)}…</span>
              </p>
            ) : (
              // Plain text on purpose: addresses in comments are never clickable.
              <p className="text comment-text">{c.text}</p>
            )}
          </article>
        );
      })}
      {more ? (
        <div className="row" style={{ justifyContent: "center" }}>
          <button type="button" onClick={loadMore} disabled={loading}>
            {loading ? "Loading…" : "Show more comments"}
          </button>
        </div>
      ) : null}

      <div className="card">
        <label className="lbl" htmlFor="comment-text">
          Add a comment
        </label>
        <input
          type="text"
          name="website"
          className="trap"
          tabIndex={-1}
          autoComplete="off"
          aria-hidden="true"
          value={trap}
          onChange={(e) => setTrap(e.target.value)}
        />
        <textarea
          id="comment-text"
          className="plain"
          rows={4}
          maxLength={MAX}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <p className="count" style={{ margin: "4px 0 0" }}>
          {text.length.toLocaleString()} / {MAX.toLocaleString()}. Comments are permanent and show
          the time they were posted. You can&apos;t edit or delete them. No name is shown, and web
          addresses can&apos;t be clicked. For extra privacy, use Tor Browser.
        </p>
        {owner && supported ? (
          <label className="opt" style={{ marginTop: 8 }}>
            <input type="checkbox" checked={asAuthor} onChange={(e) => setAsAuthor(e.target.checked)} />
            <b>Post as the author</b>
            <small>
              Only people you&apos;ve given the private link to can tell it&apos;s you. To everyone
              else it looks like an anonymous comment.
            </small>
          </label>
        ) : null}
        {err ? <p className="err">{err}</p> : null}
        <div className="row">
          <span />
          <button type="button" className="primary" onClick={post} disabled={busy || !normalise(text)}>
            {busy ? "Posting…" : "Post comment"}
          </button>
        </div>
      </div>
    </section>
  );
}

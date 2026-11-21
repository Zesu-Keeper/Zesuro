"use client";

import Link from "next/link";
import { useState } from "react";
import Stamp from "@/components/Stamp";

// A fingerprint of a file, made in this browser. The file is never uploaded or sent anywhere.
// Posting the fingerprint proves later that the file existed, unchanged, at the time of the post.

const MAX_BYTES = 300 * 1024 * 1024;

async function fingerprint(file: File): Promise<string> {
  if (file.size > MAX_BYTES) throw new Error("That file is too big to check here (the limit is 300 MB).");
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", await file.arrayBuffer()));
  return Array.from(h, (b) => b.toString(16).padStart(2, "0")).join("");
}

interface Hit {
  uid: string;
  title: string;
  createdAt: number;
}

export default function DocumentPage() {
  const [hash, setHash] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [hits, setHits] = useState<Hit[] | null>(null);
  const [note, setNote] = useState("");

  async function pick(file: File | undefined) {
    setErr(null);
    setHits(null);
    setHash(null);
    if (!file) return;
    setBusy(true);
    try {
      setName(file.name);
      setHash(await fingerprint(file));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not read that file");
    } finally {
      setBusy(false);
    }
  }

  async function lookup() {
    if (!hash) return;
    setErr(null);
    setBusy(true);
    try {
      const r = await fetch(`/api/entries?q=${hash}&limit=20`, { cache: "no-store" });
      if (!r.ok) throw new Error("Could not search the record. Try again in a moment.");
      const { entries } = (await r.json()) as { entries: (Hit & { text: string })[] };
      // Only a post that really contains this exact fingerprint counts.
      const found = entries.filter((e) => e.text.toLowerCase().includes(hash));
      found.sort((a, b) => a.createdAt - b.createdAt);
      setHits(found);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not search the record");
    } finally {
      setBusy(false);
    }
  }

  const postText = hash ? `Document fingerprint (SHA-256): ${hash}${note.trim() ? `\n\n${note.trim()}` : ""}` : "";
  const postHref = hash ? `/say#${new URLSearchParams({ title: "Document fingerprint", text: postText }).toString()}` : "#";

  return (
    <main>
      <h1>Prove a document existed</h1>
      <p className="lede">
        You can show that you had a particular file at a particular time, without showing anyone what is in it. Your
        browser makes a short fingerprint of the file. The file itself never leaves your device. If you post the
        fingerprint, the record keeps it with the time. Later, anyone who holds the exact same file can check it.{" "}
        <Link href="/help#proving-a-document-existed">More help</Link>
      </p>
      {err ? <p className="err">{err}</p> : null}

      <div className="card">
        <label className="lbl" htmlFor="file">Choose a file</label>
        <input id="file" type="file" onChange={(e) => pick(e.target.files?.[0])} />
        {busy && !hash ? <p className="meta">Working it out…</p> : null}
        {hash ? (
          <>
            <p className="meta">
              Fingerprint of <b>{name}</b>:
            </p>
            <p className="mono" style={{ wordBreak: "break-all" }}>{hash}</p>
            <div className="row" style={{ justifyContent: "flex-start" }}>
              <button type="button" onClick={lookup} disabled={busy}>Has this been recorded?</button>
            </div>
          </>
        ) : null}
      </div>

      {hits ? (
        <div className="card">
          {hits.length === 0 ? (
            <p className="empty">Nobody has recorded this fingerprint yet.</p>
          ) : (
            <>
              <p className="meta">
                This exact file was recorded {hits.length === 1 ? "once" : `${hits.length} times`}. The earliest is the
                one that counts.
              </p>
              {hits.map((h) => (
                <p key={h.uid}>
                  <Link href={`/e/${h.uid}`}>{h.title || "Untitled"}</Link> <span className="count">recorded <Stamp ms={h.createdAt} /></span>
                </p>
              ))}
              <p className="count">
                Until another site has signed a stamp made after the post, the time is only this site&apos;s word.{" "}
                <Link href="/anchors">See the stamps</Link>
              </p>
            </>
          )}
        </div>
      ) : null}

      {hash ? (
        <div className="card">
          <h2>Record it</h2>
          <p className="meta">
            This makes an ordinary post containing the fingerprint. Nobody can read the file from it. Posts normally
            appear after a delay of a few hours, and the recorded time is when it appears. Turn the delay off on the next
            screen if the exact time matters.
          </p>
          <label className="lbl" htmlFor="note">Add a note (optional, public)</label>
          <input id="note" type="text" maxLength={200} value={note} onChange={(e) => setNote(e.target.value)} />
          <div className="row" style={{ justifyContent: "flex-start" }}>
            <Link className="btn primary" href={postHref}>Go to the post screen</Link>
          </div>
          <p className="count">
            Only record fingerprints of files you are happy to be linked to. Anyone who has the same file can see that it
            was recorded.
          </p>
        </div>
      ) : null}
    </main>
  );
}

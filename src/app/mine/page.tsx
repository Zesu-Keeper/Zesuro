"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import KeyBackup from "@/components/KeyBackup";
import RedactedText from "@/components/RedactedText";
import Stamp from "@/components/Stamp";
import {
  addMine,
  decryptSecret,
  findMineIn,
  importKeyString,
  loadKey,
  loadMine,
  openingFor,
  markBackedUp,
  storeKey,
  type MineEntry,
  type StoredKey,
} from "@/lib/client-crypto";

interface Live {
  status: "anonymous" | "revealed" | "unknown";
  handle: string | null;
  revealedAt: number | null;
  revealAt: number | null;
}

export default function Mine() {
  const [mine, setMine] = useState<MineEntry[] | null>(null);
  const [live, setLive] = useState<Record<string, Live>>({});
  const [revealing, setRevealing] = useState<string | null>(null);
  const [handle, setHandle] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [backup, setBackup] = useState<StoredKey | null>(null);
  const [restoreText, setRestoreText] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const list = loadMine();
    setMine(list);
    const out: Record<string, Live> = {};
    await Promise.all(
      list.map(async (m) => {
        try {
          const r = await fetch(`/api/entries/${m.uid}`, { cache: "no-store" });
          if (r.ok) {
            const { entry } = await r.json();
            out[m.uid] = {
              status: entry.status,
              handle: entry.handle,
              revealedAt: entry.revealedAt,
              revealAt: entry.revealAt,
            };
          }
        } catch {
          /* offline: show without live status */
        }
      }),
    );
    setLive(out);
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function reveal(m: MineEntry) {
    setErr(null);
    // Dated entries reveal under the name they were sealed with, which this device kept. The name is
    // time-locked, so the server cannot supply it: if this device did not keep it (a restored key),
    // the author types one.
    const h = m.handle ? m.handle : handle.trim();
    if (!h) return setErr("Enter the name to show.");
    const key = loadKey();
    if (!key) return setErr("This device does not have the key for that entry. Restore it below.");
    try {
      const opening = await openingFor(key, m, h);
      // Releasing also opens any redacted text and hidden place, so send them with the reveal.
      let secret = m.secret ?? null;
      if (!secret) {
        const r = await fetch(`/api/entries/${m.uid}`, { cache: "no-store" });
        const blob = r.ok ? (await r.json()).entry?.secretBlob : null;
        if (blob) secret = await decryptSecret(key, m.nonce, blob);
      }
      const res = await fetch(`/api/entries/${m.uid}/reveal`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...opening, secret }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not reveal");
      setRevealing(null);
      setHandle("");
      await refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not reveal");
    }
  }

  async function restore() {
    setErr(null);
    setMsg(null);
    try {
      const k = importKeyString(restoreText);
      storeKey(k);
      markBackedUp();
      // Find which public entries this key made, without the server knowing.
      let before: number | undefined;
      let total = 0;
      for (let page = 0; page < 40; page++) {
        const r = await fetch(`/api/entries?limit=100${before ? `&before=${before}` : ""}`, {
          cache: "no-store",
        });
        const { entries } = await r.json();
        if (!entries.length) break;
        const found = await findMineIn(k, entries);
        found.forEach(addMine);
        total += found.length;
        before = entries[entries.length - 1].seq;
        if (entries.length < 100) break;
      }
      setRestoreText("");
      setMsg(`Key restored. Found ${total} of your ${total === 1 ? "entry" : "entries"}.`);
      await refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not restore that key");
    }
  }

  return (
    <main>
      <h1>Your posts</h1>
      <p className="lede">
        These are the posts you made on this device. Only you can reveal them. Using Zesuro at a different address? <Link href="/transfer">Move your keys</Link> to it.
      </p>
      {err ? <p className="err">{err}</p> : null}
      {msg ? <p className="notice">{msg}</p> : null}

      {mine === null ? null : mine.length === 0 ? (
        <p className="empty">
          You haven&apos;t posted anything from this device yet. <Link href="/say">Say something.</Link>
        </p>
      ) : (
        mine.map((m) => {
          const l = live[m.uid];
          const done = l?.status === "revealed";
          return (
            <article className="card" key={m.uid}>
              {m.title ? <h2 className="title">{m.title}</h2> : null}
              <p className="text">
                <RedactedText text={m.text} parts={m.secret?.parts ?? null} owner />
              </p>
              {m.secret?.place ? (
                <p className="place">
                  {m.secret.place.label || `${m.secret.place.lat}, ${m.secret.place.lng}`}{" "}
                  <span className="count">(hidden from the public until released)</span>
                </p>
              ) : null}
              <div className="meta">
                <span className={`badge ${l?.status ?? "anonymous"}`}>
                  {l ? l.status : "…"}
                </span>
                <span>
                  Sealed <Stamp ms={m.createdAt} />
                </span>
                {done && l.handle ? (
                  <span>
                    as <span className="who">{l.handle}</span>
                  </span>
                ) : null}
                {!done && (l?.revealAt ?? m.revealAt) ? (
                  <span>
                    Reveals <Stamp ms={(l?.revealAt ?? m.revealAt) as number} />
                  </span>
                ) : null}
                <Link href={`/e/${m.uid}`}>Open</Link>
              </div>

              {!done && m.mode !== "locked" ? (
                revealing === m.uid ? (
                  <div style={{ marginTop: 12 }}>
                    {m.handle ? (
                      <p className="count">
                        Reveals now as <span className="who">{m.handle}</span>, the name
                        you sealed it with.
                      </p>
                    ) : (
                      <>
                        <label className="lbl" htmlFor={`h-${m.uid}`}>
                          Name to show on this entry
                        </label>
                        {m.mode === "date" ? (
                          <p className="count">
                            This device didn&apos;t keep the name you posted with. The name you type
                            here will be shown now. The name you originally locked in will still open on the date.
                          </p>
                        ) : null}
                        <input
                          id={`h-${m.uid}`}
                          type="text"
                          maxLength={40}
                          value={handle}
                          onChange={(e) => setHandle(e.target.value)}
                        />
                      </>
                    )}
                    {m.secret ? (
                      <p className="count">
                        This will also show the words and place you hid.
                      </p>
                    ) : null}
                    <div className="row">
                      <button
                        className="link"
                        onClick={() => {
                          setRevealing(null);
                          setErr(null);
                        }}
                      >
                        Cancel
                      </button>
                      <button className="primary" onClick={() => reveal(m)}>
                        Reveal now
                      </button>
                    </div>
                  </div>
                ) : (
                  <div style={{ marginTop: 12 }}>
                    <button
                      onClick={() => {
                        setRevealing(m.uid);
                        setErr(null);
                      }}
                    >
                      Reveal
                    </button>
                  </div>
                )
              ) : null}
              {!done && m.mode === "locked" ? (
                <p className="meta" style={{ marginTop: 10 }}>
                  Locked. It will reveal on its date.
                </p>
              ) : null}
            </article>
          );
        })
      )}

      <h1 style={{ fontSize: "1.1rem", marginTop: 32 }}>Your key</h1>
      {backup ? (
        <div className="card">
          <KeyBackup
            k={backup}
            confirmLabel="Done"
            onCancel={() => setBackup(null)}
            onConfirmed={() => {
              markBackedUp();
              setBackup(null);
            }}
          />
        </div>
      ) : (
        <button
          onClick={() => {
            const k = loadKey();
            if (!k) setErr("There is no key on this device yet. Post something first.");
            else setBackup(k);
          }}
        >
          Show backup QR
        </button>
      )}
      <details style={{ marginTop: 16 }}>
        <summary>Restore a key on this device</summary>
        <label className="lbl" htmlFor="restore">
          Paste the key text (starts with whenisaid-key:v1:)
        </label>
        <textarea
          id="restore"
          className="plain"
          rows={3}
          value={restoreText}
          onChange={(e) => setRestoreText(e.target.value)}
          style={{ width: "100%" }}
        />
        <div className="row">
          <span />
          <button disabled={!restoreText.trim()} onClick={restore}>
            Restore
          </button>
        </div>
      </details>
    </main>
  );
}

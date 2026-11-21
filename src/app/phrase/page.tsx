"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { addMine, findMineIn, loadKey, markBackedUp, storeKey, type StoredKey } from "@/lib/client-crypto";
import { keyCheckCode, makePhrase, phraseToKey, readPhrase } from "@/lib/phrase";

// A key you can remember. The words are the whole key: they make the same key on any device.

async function scanRecord(k: StoredKey): Promise<number> {
  let before: number | undefined;
  let total = 0;
  for (let page = 0; page < 40; page++) {
    const r = await fetch(`/api/entries?limit=100${before ? `&before=${before}` : ""}`, { cache: "no-store" });
    const { entries } = await r.json();
    if (!entries.length) break;
    const found = await findMineIn(k, entries);
    found.forEach(addMine);
    total += found.length;
    before = entries[entries.length - 1].seq;
    if (entries.length < 100) break;
  }
  return total;
}

export default function PhrasePage() {
  const [hasKey, setHasKey] = useState<boolean | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // make
  const [words, setWords] = useState<string[] | null>(null);
  const [made, setMade] = useState<{ key: StoredKey; code: string } | null>(null);
  const [confirmText, setConfirmText] = useState("");

  // restore
  const [typed, setTyped] = useState("");
  const [checked, setChecked] = useState<{ key: StoredKey; code: string } | null>(null);

  useEffect(() => {
    setHasKey(!!loadKey());
  }, []);

  async function make() {
    setErr(null);
    setMsg(null);
    setBusy(true);
    try {
      const w = makePhrase();
      const key = await phraseToKey(w);
      setWords(w);
      setMade({ key, code: await keyCheckCode(key) });
      setConfirmText("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not make the words");
    } finally {
      setBusy(false);
    }
  }

  function keep() {
    if (!words || !made) return;
    const again = readPhrase(confirmText);
    if (!again || again.join(" ") !== words.join(" ")) return setErr("Those are not the same six words. Check them against what is on the screen.");
    storeKey(made.key);
    markBackedUp();
    setHasKey(true);
    setWords(null);
    setMade(null);
    setConfirmText("");
    setErr(null);
    setMsg("Done. This device now uses your six-word key. Nothing else needs saving.");
  }

  async function check() {
    setErr(null);
    setMsg(null);
    setChecked(null);
    const w = readPhrase(typed);
    if (!w) return setErr("That isn't six words from the list. Check the spelling and that you have all six.");
    setBusy(true);
    try {
      const key = await phraseToKey(w);
      setChecked({ key, code: await keyCheckCode(key) });
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not check the words");
    } finally {
      setBusy(false);
    }
  }

  async function use() {
    if (!checked) return;
    const current = loadKey();
    if (current && current.priv.d !== checked.key.priv.d) {
      if (
        !window.confirm(
          "This device already has a different key.\n\nIf you replace it, you can't reveal posts made with the old key unless you saved a backup of it. Replace it?",
        )
      )
        return;
    }
    setErr(null);
    setBusy(true);
    try {
      storeKey(checked.key);
      markBackedUp();
      setHasKey(true);
      const total = await scanRecord(checked.key);
      setTyped("");
      setChecked(null);
      setMsg(`Key restored. Found ${total} of your ${total === 1 ? "post" : "posts"}.`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not restore the key");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      <h1>Six-word key</h1>
      <p className="lede">
        A six-word key is a key you can remember or write on paper. The six words are all you need: nothing else is
        saved anywhere, and the same six words work on any device.{" "}
        <Link href="/help#your-key">More help</Link>
      </p>
      {msg ? <p className="notice">{msg}</p> : null}
      {err ? <p className="err">{err}</p> : null}

      <div className="card">
        <h2>Make a six-word key</h2>
        {hasKey ? (
          <p className="meta">
            This device already has a key. Switching to a six-word key would cut you off from the posts you have made
            with it. To use six words, make them in a browser that has no Zesuro key yet.
          </p>
        ) : !words ? (
          <>
            <p className="meta">You will get six random words. Write them down. Only use the words this page gives you.</p>
            <button type="button" className="primary" onClick={make} disabled={busy || hasKey === null}>
              {busy ? "Making your key…" : "Make my six words"}
            </button>
          </>
        ) : (
          <>
            <p className="mono" style={{ fontSize: "1.4rem", lineHeight: 1.6 }} aria-label="Your six words">
              {words.map((w, i) => (
                <span key={i}>
                  {i + 1}. {w}
                  <br />
                </span>
              ))}
            </p>
            <p className="meta">
              Key check code: <b className="mono">{made?.code}</b>. Write it down too. When you type the words again
              later, you should see the same code.
            </p>
            <div className="warnbox">
              Write these six words on paper now. Anyone who has them can post and reveal as you. If you lose them and
              this device is wiped, you can never reveal your posts. Don&apos;t save them in a file on a device someone
              else might search.
            </div>
            <label className="lbl" htmlFor="confirm">Type the six words to confirm you have them</label>
            <input
              id="confirm"
              type="text"
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <div className="row">
              <button type="button" className="link" onClick={() => { setWords(null); setMade(null); setErr(null); }}>
                Start again
              </button>
              <button type="button" className="primary" onClick={keep} disabled={!confirmText.trim()}>
                Use these words as my key
              </button>
            </div>
          </>
        )}
      </div>

      <div className="card" id="restore">
        <h2>Use six words you already have</h2>
        <p className="meta">Type your six words. This device will make the same key and find your posts.</p>
        <input
          type="text"
          placeholder="six words"
          value={typed}
          onChange={(e) => { setTyped(e.target.value); setChecked(null); }}
          autoComplete="off"
          spellCheck={false}
          aria-label="Your six words"
        />
        <div className="row">
          <span />
          <button type="button" onClick={check} disabled={busy || !typed.trim()}>
            {busy && !checked ? "Checking…" : "Check the words"}
          </button>
        </div>
        {checked ? (
          <>
            <p className="meta">
              Key check code: <b className="mono">{checked.code}</b>. It should match the code you wrote down when you
              made the words. If it doesn&apos;t, you made a typing mistake.
            </p>
            <button type="button" className="primary" onClick={use} disabled={busy}>
              {busy ? "Restoring…" : "Use this key on this device"}
            </button>
          </>
        ) : null}
      </div>

      <p className="count">
        Your posts are under <Link href="/mine">Your posts</Link>.
      </p>
    </main>
  );
}

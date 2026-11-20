"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import KeyBackup from "@/components/KeyBackup";
import ShareButton from "@/components/ShareButton";
import { postWithTicket, warmTicket } from "@/lib/ticket-client";
import PlaceMap, { type Pin } from "@/components/PlaceMap";
import RedactedText from "@/components/RedactedText";
import Stamp from "@/components/Stamp";
import { normText, normTitle, type CommitContent } from "@/lib/commit";
import { encodeBundle } from "@/lib/release-bundle";
import { roundForTime, timelockEncrypt } from "@/lib/timelock";
import {
  addMine,
  cleanLabel,
  commitmentV2,
  encryptSecret,
  entryKeysSupported,
  getOrCreateKey,
  isBackedUp,
  makeOpeningV2,
  makeSecret,
  markBackedUp,
  randomHex,
  roundPlace,
  secretCommitOf,
  splitRedactions,
  type Secret,
  type StoredKey,
} from "@/lib/client-crypto";

type PlaceMode = "none" | "public" | "hidden";

type Mode = "manual" | "date" | "locked";

/** Date is required, time is optional. No time means start of day (reveal) or end of day (deadline). */
function toMs(date: string, time: string, whenBlank: "start" | "end"): number | null {
  if (!date) return null;
  const t = time || (whenBlank === "start" ? "00:00:00" : "23:59:59");
  const ms = new Date(`${date}T${t}`).getTime(); // no "Z": read as the user's local time
  return Number.isFinite(ms) ? ms : null;
}

function describe(ms: number | null): string | null {
  return ms === null
    ? null
    : new Date(ms).toLocaleString(undefined, { dateStyle: "full", timeStyle: "short" });
}

export default function SayIt() {
  const [title, setTitle] = useState("");
  const [text, setText] = useState("");
  const [placeMode, setPlaceMode] = useState<PlaceMode>("none");
  const [pin, setPin] = useState<Pin | null>(null);
  const [placeLabel, setPlaceLabel] = useState("");
  const [hint, setHint] = useState<string | null>(null);
  const split = splitRedactions(text);
  const hiddenCount = split.parts.length + (placeMode === "hidden" ? 1 : 0);
  const [sheet, setSheet] = useState(false);
  const [mode, setMode] = useState<Mode>("manual");
  const [whenDate, setWhenDate] = useState("");
  const [whenTime, setWhenTime] = useState("");
  const [handle, setHandle] = useState("");
  const [showDate, setShowDate] = useState(false);
  const [useDeadline, setUseDeadline] = useState(false);
  const [deadlineDate, setDeadlineDate] = useState("");
  const [deadlineTime, setDeadlineTime] = useState("");
  const revealMs = toMs(whenDate, whenTime, "start");
  const deadlineMs = toMs(deadlineDate, deadlineTime, "end");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [backupKey, setBackupKey] = useState<StoredKey | null>(null);
  // A field people never see. Scripts that fill in every field give themselves away.
  const [trap, setTrap] = useState("");
  useEffect(() => {
    warmTicket();
  }, []);
  const [done, setDone] = useState<{ uid: string; createdAt: number } | null>(null);
  const box = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    box.current?.focus();
  }, []);

  function redactSelection() {
    const ta = box.current;
    if (!ta) return;
    const { selectionStart: a, selectionEnd: b } = ta;
    if (a === b) {
      setHint("Select the words you want to hide first, then tap this.");
      return;
    }
    setHint(null);
    setText(text.slice(0, a) + "[[" + text.slice(a, b) + "]]" + text.slice(b));
  }

  function useMyLocation() {
    setHint(null);
    if (!navigator.geolocation) return setHint("This browser can't find your location. Tap the map instead.");
    navigator.geolocation.getCurrentPosition(
      // About 1 km. A phone knows where it is to a metre; the record has no use for that.
      (p) =>
        setPin({
          lat: Math.round(p.coords.latitude * 100) / 100,
          lng: Math.round(p.coords.longitude * 100) / 100,
        }),
      () => setHint("Couldn't get your location. Tap the map instead."),
      { enableHighAccuracy: false, timeout: 10_000 },
    );
  }

  function validate(): string | null {
    if (!title.trim()) return "Add a title.";
    if (placeMode !== "none" && !pin) return "Tap the map to drop a pin, or choose no place.";
    if (mode !== "manual") {
      if (!revealMs) return "Choose the date to reveal.";
      if (revealMs < Date.now() + 60_000)
        return whenTime
          ? "That time has already passed. Pick a later time."
          : "That date has already started. Pick a later date, or add a time later today.";
    }
    if (!handle.trim()) return "Enter the name you want shown when it's revealed.";
    if (useDeadline) {
      if (!deadlineMs) return "Choose the deadline date.";
      if (deadlineMs < Date.now() + 60_000)
        return "That deadline has already passed. Pick a later date.";
    }
    return null;
  }

  async function onSeal() {
    setError(null);
    const v = validate();
    if (v) return setError(v);
    // Locked entries can never be revealed early, so only they don't need the key.
    if (mode !== "locked" && !isBackedUp()) {
      setBackupKey(await getOrCreateKey());
      return;
    }
    await doSeal();
  }

  async function doSeal() {
    setBusy(true);
    setError(null);
    try {
      if (!(await entryKeysSupported()))
        throw new Error("This browser is too old to seal entries. Use a current Firefox, Chrome or Safari.");
      const key = await getOrCreateKey();
      const uid = crypto.randomUUID();
      const nonce = randomHex(16);
      const revealAt = mode === "manual" ? null : revealMs;
      const deadlineAt = useDeadline ? deadlineMs : null;

      // Redactions and a hidden place are sealed as one payload; only its commitment is public.
      const { publicText, parts } = splitRedactions(text);
      const placeVal = pin && placeMode !== "none" ? { ...pin, label: placeLabel } : null;
      let secret: Secret | null = null;
      if (parts.length > 0 || placeMode === "hidden")
        secret = makeSecret(parts, placeMode === "hidden" ? placeVal : null);
      const secretCommit = secret ? await secretCommitOf(secret) : null;
      const secretBlob = secret ? await encryptSecret(key, nonce, secret) : null;

      // The commitment covers exactly what the site will record, so what the author later
      // opens can only ever match this text, this title, this place and this entry id.
      const content: CommitContent = {
        uid,
        title: normTitle(title),
        text: normText(publicText),
        placeMode,
        place:
          placeMode === "public" && placeVal
            ? { lat: roundPlace(placeVal.lat), lng: roundPlace(placeVal.lng), label: cleanLabel(placeVal.label) }
            : null,
        secretCommit,
        mode,
      };
      const commitment = await commitmentV2(key, nonce, content);
      // Dated and locked entries: the name and the hidden parts are encrypted here, in the browser, to the
      // drand round of the reveal date. Only the ciphertext is sent. Nobody, the server included, can read
      // it before that round is published; after it, the server opens it and checks it against the commitment.
      let timelock: { round: number; ct: string } | null = null;
      if (mode !== "manual") {
        const opening = await makeOpeningV2(key, uid, nonce, handle.trim());
        const round = roundForTime(revealAt!);
        timelock = { round, ct: timelockEncrypt(encodeBundle({ opening, secret }), round) };
      }

      const res = await postWithTicket(
        "/api/entries",
        {
          uid,
          title: content.title,
          text: content.text,
          placeMode,
          place: content.place,
          commitV: 2,
          secretCommit,
          secretBlob,
          // Never sent in the clear: a dated or locked entry's hidden parts travel inside the time-lock.
          secret: null,
          commitment,
          nonce,
          mode,
          revealAt,
          deadlineAt,
          opening: null,
          timelock,
          revealPublic: mode !== "manual" && showDate,
        },
        trap,
      );
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not seal that");

      addMine({
        uid,
        nonce,
        title: data.entry.title,
        text: data.entry.text,
        createdAt: data.entry.createdAt,
        mode,
        revealAt,
        handle: handle.trim(),
        secret,
        commitV: 2,
      });
      setDone({ uid, createdAt: data.entry.createdAt });
      setTitle("");
      setPlaceMode("none");
      setPin(null);
      setPlaceLabel("");
      setHint(null);
      setText("");
      setSheet(false);
      setBackupKey(null);
      setMode("manual");
      setWhenDate("");
      setWhenTime("");
      setShowDate(false);
      setHandle("");
      setUseDeadline(false);
      setDeadlineDate("");
      setDeadlineTime("");
      box.current?.focus();
    } catch (e) {
      setBackupKey(null); // back to the options sheet so the error is visible
      setError(e instanceof Error ? e.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      {done ? (
        <div className="notice" role="status">
          Sealed ✓ <Stamp ms={done.createdAt} /> ·{" "}
          <Link href={`/e/${done.uid}`}>View entry</Link>{" "}
          <ShareButton uid={done.uid} title="" />
        </div>
      ) : null}

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
      <input
        type="text"
        className="title"
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        placeholder="Title (public)"
        maxLength={100}
        aria-label="Title"
      />
      <textarea
        ref={box}
        className="say"
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="Say it. It will be recorded exactly as you write it."
        maxLength={5000}
        aria-label="What do you want to say?"
      />
      <div className="row">
        <button type="button" className="link" onClick={redactSelection}>
          Hide selected words
        </button>
        <span className="count">{text.length.toLocaleString()} / 5,000</span>
      </div>
      {split.parts.length > 0 ? (
        <div className="preview" aria-label="What the public will see">
          <span className="count">What the public sees until it is released:</span>
          <br />
          <RedactedText text={split.publicText} parts={null} />
        </div>
      ) : (
        <p className="count" style={{ margin: "0 0 8px" }}>
          To hide a name or detail until release, select it and tap &ldquo;Hide selected
          words&rdquo;, or type it inside [[double brackets]].
        </p>
      )}

      <details className="field" open={placeMode !== "none"}>
        <summary>Add a place (optional)</summary>
        <label className="opt" style={{ marginTop: 8 }}>
          <input
            type="radio"
            name="placemode"
            checked={placeMode === "none"}
            onChange={() => setPlaceMode("none")}
          />
          <b>No place</b>
        </label>
        <label className="opt">
          <input
            type="radio"
            name="placemode"
            checked={placeMode === "public"}
            onChange={() => setPlaceMode("public")}
          />
          <b>Show the place now</b>
        </label>
        <label className="opt">
          <input
            type="radio"
            name="placemode"
            checked={placeMode === "hidden"}
            onChange={() => setPlaceMode("hidden")}
          />
          <b>Hide the place until it is released</b>
          <small>The public sees that a place exists, but not where.</small>
        </label>
        {placeMode !== "none" ? (
          <>
            <PlaceMap pin={pin} onPick={setPin} />
            <div className="row" style={{ marginTop: 0 }}>
              <button type="button" onClick={useMyLocation}>
                Use my location
              </button>
              <span className="count">
                {pin ? `${pin.lat.toFixed(5)}, ${pin.lng.toFixed(5)}` : "Tap the map to drop a pin"}
              </span>
            </div>
            <label className="lbl" htmlFor="place-label">
              Name of the place (optional)
            </label>
            <input
              id="place-label"
              type="text"
              value={placeLabel}
              maxLength={80}
              onChange={(e) => setPlaceLabel(e.target.value)}
              placeholder="e.g. Central Station"
            />
            <p className="count" style={{ margin: "6px 0 0" }}>
              The map pictures come from OpenStreetMap, which can see which part of the map you look at.
            </p>
          </>
        ) : null}
      </details>
      {hint ? <p className="err">{hint}</p> : null}

      <div className="row">
        <span />
        <button
          className="primary"
          disabled={text.trim().length === 0 || title.trim().length === 0}
          onClick={() => {
            setError(null);
            setSheet(true);
          }}
        >
          Seal
        </button>
      </div>

      {sheet ? (
        <div
          className="sheet-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget && !busy) {
              setSheet(false);
              setBackupKey(null);
            }
          }}
        >
          <div className="sheet" role="dialog" aria-modal="true" aria-label="Seal this">
            {backupKey ? (
              <KeyBackup
                k={backupKey}
                confirmLabel="Save key & seal"
                onCancel={() => setBackupKey(null)}
                onSkip={
                  mode === "date"
                    ? async () => {
                        setBackupKey(null);
                        await doSeal();
                      }
                    : undefined
                }
                onConfirmed={async () => {
                  markBackedUp();
                  await doSeal();
                }}
              />
            ) : (
              <>
                <h2>When do you reveal who said it?</h2>
                <p className="lede">The words are public now. Your name stays hidden until then.</p>
                {hiddenCount > 0 ? (
                  <p className="lede">
                    {split.parts.length > 0
                      ? `${split.parts.length} hidden ${split.parts.length === 1 ? "passage" : "passages"}`
                      : ""}
                    {split.parts.length > 0 && placeMode === "hidden" ? " and " : ""}
                    {placeMode === "hidden" ? "a hidden place" : ""} will open at the same moment
                    as your name.
                  </p>
                ) : null}

                <label className="opt">
                  <input
                    type="radio"
                    name="mode"
                    checked={mode === "manual"}
                    onChange={() => setMode("manual")}
                  />
                  <b>I&apos;ll decide later</b>
                  <small>You press Reveal whenever you choose.</small>
                </label>

                <label className="opt">
                  <input
                    type="radio"
                    name="mode"
                    checked={mode === "date"}
                    onChange={() => setMode("date")}
                  />
                  <b>On a date and time</b>
                  <small>Revealed automatically. You can still reveal sooner.</small>
                </label>

                <label className="opt">
                  <input
                    type="radio"
                    name="mode"
                    checked={mode === "locked"}
                    onChange={() => setMode("locked")}
                  />
                  <b>No matter what</b>
                  <small>
                    Revealed on that date and can&apos;t be stopped. Your name and any hidden parts are locked in your browser until that time, so nobody can read them early, not even this site. When the time comes, the site opens them automatically.
                  </small>
                </label>

                {mode !== "manual" ? (
                  <div className="field">
                    <label className="lbl" htmlFor="when-date">
                      Reveal on (date)
                    </label>
                    <input
                      id="when-date"
                      type="date"
                      value={whenDate}
                      onChange={(e) => setWhenDate(e.target.value)}
                    />
                    <label className="lbl" htmlFor="when-time">
                      Time (optional)
                    </label>
                    <input
                      id="when-time"
                      type="time"
                      value={whenTime}
                      onChange={(e) => setWhenTime(e.target.value)}
                    />
                    <p className="count" style={{ margin: "6px 0 0" }}>
                      {revealMs
                        ? `Reveals ${describe(revealMs)} (your time)${whenTime ? "" : ", the start of that day"}.`
                        : "Pick a date. Leave the time blank for the start of the day."}
                    </p>
                    <label className="opt" style={{ margin: "10px 0 0 -26px" }}>
                      <input
                        type="checkbox"
                        checked={showDate}
                        onChange={(e) => setShowDate(e.target.checked)}
                      />
                      <b>Show the reveal date publicly</b>
                      <small>
                        If you leave this off, people can see a reveal is planned, but not when.
                        It still happens on time.
                      </small>
                    </label>
                  </div>
                ) : null}

                <div className="field">
                  <label className="lbl" htmlFor="handle">
                    Your name (required)
                  </label>
                  <input
                    id="handle"
                    type="text"
                    value={handle}
                    maxLength={40}
                    onChange={(e) => setHandle(e.target.value)}
                    placeholder="e.g. Alex R."
                  />
                  <p className="count" style={{ margin: "6px 0 0" }}>
                    Every post has a name. Nobody can see it until it&apos;s revealed
                    {mode === "manual" ? ". You reveal it yourself from My posts. The name is kept in this browser with your key, so back the key up." : ", on the date you chose."}
                  </p>
                </div>

                <details style={{ marginTop: 12 }}>
                  <summary>More options</summary>
                  <label className="opt" style={{ marginTop: 8 }}>
                    <input
                      type="checkbox"
                      checked={useDeadline}
                      onChange={(e) => setUseDeadline(e.target.checked)}
                    />
                    <b>Mark it &quot;Unknown&quot; if I haven&apos;t revealed it by a deadline</b>
                    <small>
                      After the deadline, the post is listed as Unknown. You can still reveal it
                      later.
                    </small>
                  </label>
                  {useDeadline ? (
                    <div className="field">
                      <label className="lbl" htmlFor="deadline-date">
                        Deadline (date)
                      </label>
                      <input
                        id="deadline-date"
                        type="date"
                        value={deadlineDate}
                        onChange={(e) => setDeadlineDate(e.target.value)}
                      />
                      <label className="lbl" htmlFor="deadline-time">
                        Time (optional)
                      </label>
                      <input
                        id="deadline-time"
                        type="time"
                        value={deadlineTime}
                        onChange={(e) => setDeadlineTime(e.target.value)}
                      />
                      <p className="count" style={{ margin: "6px 0 0" }}>
                        {deadlineMs
                          ? `Unknown after ${describe(deadlineMs)}${deadlineTime ? "" : " (the end of that day)"}.`
                          : "Pick a date. Leave the time blank for the end of the day."}
                      </p>
                    </div>
                  ) : null}
                </details>

                <div className="warnbox">
                  Sealing is final. You can&apos;t edit or delete this
                  {mode === "locked" ? ", and a locked reveal can't be cancelled" : ""}.
                </div>
                {error ? <p className="err">{error}</p> : null}
                <div className="row">
                  <button className="link" onClick={() => setSheet(false)} disabled={busy}>
                    Back
                  </button>
                  <button className="primary" onClick={onSeal} disabled={busy}>
                    {busy ? "Sealing…" : "Seal it"}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      ) : null}
    </main>
  );
}

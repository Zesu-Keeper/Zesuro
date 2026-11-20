"use client";

import { useEffect, useState } from "react";

const KEY = "zesuro.safety.v1";
const QUESTIONS = [
  "Is this a work, school or shared device?",
  "Are you on a work or school network, or one someone else manages?",
  "Does anyone else ever look at this phone or computer?",
];

/**
 * Three quick questions before writing. Most people who are found are found through the device or network they
 * used, not through broken encryption. The answers are kept only for this tab and never leave the browser.
 */
export default function SafetyCheck({ viaTor, onion }: { viaTor: boolean; onion: string | null }) {
  const [open, setOpen] = useState(false);
  const [yes, setYes] = useState<boolean[]>([false, false, false]);
  useEffect(() => {
    try {
      setOpen(sessionStorage.getItem(KEY) !== "done");
    } catch {
      setOpen(true);
    }
  }, []);
  const any = yes.some(Boolean);

  function finish() {
    try {
      sessionStorage.setItem(KEY, "done");
    } catch {
      /* not kept: it shows again next time */
    }
    setOpen(false);
  }

  if (!open)
    return (
      <p className="count safety-mini">
        Safety check done.{" "}
        <button type="button" className="link" onClick={() => setOpen(true)}>Show it again</button>
        {" · "}Press Esc twice to leave quickly.
      </p>
    );

  return (
    <div className="card safety">
      <h2 className="title">Before you write: a quick safety check</h2>
      <p className="count">Answer for yourself. Nothing here is saved or sent.</p>
      {QUESTIONS.map((q, i) => (
        <label className="opt" key={q}>
          <input
            type="checkbox"
            checked={yes[i]}
            onChange={(e) => setYes((y) => y.map((v, k) => (k === i ? e.target.checked : v)))}
          />
          <b>{q}</b>
        </label>
      ))}
      {any ? (
        <div className="warnbox">
          <b>Stop here if you can.</b> A work or shared device, or a network someone else runs, can record what you
          do, including what you type here. Use a personal phone or computer on a network nobody you know controls,
          like a café or library, and ideally use Tor Browser.
        </div>
      ) : null}
      {!viaTor ? (
        <p className="count">
          Safest of all: use <a href="https://www.torproject.org/download/" rel="noreferrer">Tor Browser</a>. It hides
          from your internet provider that you visited this site.
          {onion ? (
            <>
              {" "}In Tor Browser, use this address: <span className="mono" style={{ wordBreak: "break-all" }}>{onion}</span>
            </>
          ) : null}
        </p>
      ) : (
        <p className="count">You are using the onion address through Tor. Good.</p>
      )}
      <p className="count">
        Remember: details like names, dates, numbers and places identify writers far more often than anything
        technical. The page will point them out as you type.
      </p>
      <div className="row" style={{ justifyContent: "flex-start" }}>
        <button type="button" className="primary" onClick={finish}>
          {any ? "I understand, continue anyway" : "Continue"}
        </button>
      </div>
    </div>
  );
}

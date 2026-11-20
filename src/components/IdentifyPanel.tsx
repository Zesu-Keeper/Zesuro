"use client";

import { useMemo } from "react";
import { findIdentifying, hiddenMarks, KIND_LABEL } from "@/lib/identify";

/** Points out what in the text could identify the writer, with a one-tap way to hide each detail until reveal. */
export default function IdentifyPanel({
  text,
  onHide,
  onClean,
}: {
  text: string;
  onHide: (phrase: string) => void;
  onClean: () => void;
}) {
  const found = useMemo(() => findIdentifying(text), [text]);
  const marks = useMemo(() => hiddenMarks(text), [text]);
  const tagged = marks.invisible + marks.lookalike > 0;
  if (!found.length && !tagged) return null;
  return (
    <div className="card identify" aria-live="polite">
      {tagged ? (
        <div className="warnbox">
          <b>This text contains hidden marks.</b> It has {marks.invisible ? `${marks.invisible} invisible character${marks.invisible === 1 ? "" : "s"}` : ""}
          {marks.invisible && marks.lookalike ? " and " : ""}
          {marks.lookalike ? `${marks.lookalike} letter${marks.lookalike === 1 ? "" : "s"} that look like ordinary ones but aren't` : ""}.
          Documents handed out at work are sometimes tagged like this, so each copy can be traced to one person.{" "}
          <button type="button" className="link" onClick={onClean}>Remove them</button>
          <br />
          Wording can be tagged too: if you copied text from a document, put it in your own words.
        </div>
      ) : null}
      {found.length ? (
        <>
          <p className="count" style={{ marginTop: 0 }}>
            <b>These could identify you.</b> How many people know each one? Details only a few people know are how most
            writers are found. Change them, leave them out, or hide them until you reveal.
          </p>
          <ul className="identify-list">
            {found.map((f) => (
              <li key={f.kind + f.text}>
                <span className="mono">{f.text}</span> <span className="count">({KIND_LABEL[f.kind]})</span>{" "}
                <button type="button" className="link" onClick={() => onHide(f.text)}>Hide until reveal</button>
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </div>
  );
}

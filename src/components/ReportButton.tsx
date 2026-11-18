"use client";

import { useEffect, useState } from "react";
import { postWithTicket, warmTicket } from "@/lib/ticket-client";
import { voterTokenFor } from "@/lib/voter";

const STORE = "whenisaid.reported.v1";

function load(): Record<string, 1> {
  try {
    return JSON.parse(localStorage.getItem(STORE) || "{}") as Record<string, 1>;
  } catch {
    return {};
  }
}

/**
 * Spam flag and its counter, for an entry (id = its uid) or a comment (id = its number).
 * Flags never hide or remove anything; on entries they lower the ranking.
 */
export default function ReportButton({
  kind,
  id,
  count,
}: {
  kind: "entry" | "comment";
  id: string;
  count: number;
}) {
  const key = `${kind}:${id}`;
  const [state, setState] = useState<"idle" | "busy" | "done" | "failed">("idle");
  const [msg, setMsg] = useState("");
  const [n, setN] = useState(count);

  useEffect(() => {
    if (load()[key]) setState("done");
    else warmTicket();
  }, [key]);

  async function report() {
    const voter = await voterTokenFor(`flag:${kind}:${id}`);
    if (!voter) {
      setMsg("Flagging needs browser storage turned on.");
      return setState("failed");
    }
    setState("busy");
    try {
      const url = kind === "entry" ? `/api/entries/${id}/report` : `/api/comments/${id}/report`;
      // Flags carry a one-use form ticket, so a script can't pour them in.
      const res = await postWithTicket(url, { voter }, "");
      const data = await res.json().catch(() => ({}));
      if (!res.ok && res.status !== 429) throw new Error(data.error || "Could not flag");
      if (typeof data.reports === "number") setN(data.reports);
      try {
        const all = load();
        all[key] = 1;
        localStorage.setItem(STORE, JSON.stringify(all));
      } catch {
        /* ignore */
      }
      setState("done");
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Could not flag");
      setState("failed");
    }
  }

  const tally = n > 0 ? ` · ${n.toLocaleString("en")}` : "";
  if (state === "done")
    return (
      <span className={`count spam${n > 0 ? " flagged" : ""}`}>Flagged as spam{tally}</span>
    );
  return (
    <>
      <button
        type="button"
        className={`link report${n > 0 ? " flagged" : ""}`}
        onClick={report}
        disabled={state === "busy"}
        title="Flag as spam. Flags are counted in public and push an entry down the ranking; nothing is hidden or removed."
      >
        Spam{tally}
      </button>
      {state === "failed" ? <span className="err">{msg}</span> : null}
    </>
  );
}

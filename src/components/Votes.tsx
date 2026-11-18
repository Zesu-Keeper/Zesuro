"use client";

import { useEffect, useState } from "react";
import { voterTokenFor } from "@/lib/voter";

type Vote = -1 | 0 | 1;
type Kind = "like" | "outcome";

const KIND = {
  like: {
    store: "whenisaid.votes.v1",
    path: "vote",
    up: { icon: "▲", label: "Like" },
    down: { icon: "▼", label: "Dislike" },
  },
  outcome: {
    store: "whenisaid.outcomes.v1",
    path: "outcome",
    up: { icon: "✓", label: "It happened" },
    down: { icon: "✗", label: "It didn't" },
  },
} as const;

function loadVotes(kind: Kind): Record<string, Vote> {
  try {
    return JSON.parse(localStorage.getItem(KIND[kind].store) || "{}") as Record<string, Vote>;
  } catch {
    return {};
  }
}

function saveVote(kind: Kind, uid: string, v: Vote) {
  try {
    const all = loadVotes(kind);
    if (v === 0) delete all[uid];
    else all[uid] = v;
    localStorage.setItem(KIND[kind].store, JSON.stringify(all));
  } catch {
    /* storage blocked: the vote still counts, it just won't be highlighted next time */
  }
}

export default function Votes({
  uid,
  up,
  down,
  kind = "like",
}: {
  uid: string;
  up: number;
  down: number;
  kind?: Kind;
}) {
  const K = KIND[kind];
  const [counts, setCounts] = useState({ up, down });
  const [mine, setMine] = useState<Vote>(0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setMine(loadVotes(kind)[uid] ?? 0);
  }, [uid, kind]);

  async function cast(v: Vote) {
    if (busy) return;
    const value: Vote = mine === v ? 0 : v; // pressing the same button again takes it back
    const voter = await voterTokenFor(`${kind}:${uid}`);
    if (!voter) return setErr("Voting needs browser storage turned on.");
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch(`/api/entries/${uid}/${K.path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ voter, value }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Could not vote");
      setCounts({ up: data.up, down: data.down });
      setMine(data.mine);
      saveVote(kind, uid, data.mine);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not vote");
    } finally {
      setBusy(false);
    }
  }

  return (
    <span className={`votes ${kind}`} role="group" aria-label={kind === "outcome" ? "Did it happen?" : "Votes"}>
      {kind === "outcome" ? <span className="count">Did it happen?</span> : null}
      <button
        type="button"
        className={`vote${mine === 1 ? " on" : ""}`}
        aria-pressed={mine === 1}
        aria-label={`${K.up.label} (${counts.up})`}
        disabled={busy}
        onClick={() => cast(1)}
      >
        <span aria-hidden="true">{K.up.icon}</span>
        {kind === "outcome" ? ` Happened` : ""} {counts.up}
      </button>
      <button
        type="button"
        className={`vote down${mine === -1 ? " on" : ""}`}
        aria-pressed={mine === -1}
        aria-label={`${K.down.label} (${counts.down})`}
        disabled={busy}
        onClick={() => cast(-1)}
      >
        <span aria-hidden="true">{K.down.icon}</span>
        {kind === "outcome" ? ` Didn't` : ""} {counts.down}
      </button>
      {err ? <span className="err" role="status">{err}</span> : null}
    </span>
  );
}

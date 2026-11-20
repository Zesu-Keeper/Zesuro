// Browser only. Forms fetch a ticket when they open and send it with the post; the server
// refuses posts without one, sent implausibly fast, or reusing one (see lib/spam.ts). A ticket
// works once, so each post uses up the one in hand and a fresh one is fetched for the next.

import { site } from "./site";

let cur: { ticket: string; at: number } | null = null;
let inflight: Promise<void> | null = null;
const WAIT_MS = 2_300;
const REFRESH_MS = 11 * 3_600_000;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function fresh(): Promise<void> {
  // One fetch at a time, however many buttons on the page ask for a ticket together.
  return (inflight ??= (async () => {
    try {
      const r = await fetch(site("/api/ticket"), { cache: "no-store" });
      const d = await r.json();
      if (!r.ok || typeof d.ticket !== "string") throw new Error(d.error || "Could not prepare the form");
      cur = { ticket: d.ticket, at: Date.now() };
    } finally {
      inflight = null;
    }
  })());
}

/** Call when a form appears, so the ticket is ready by the time the person has typed. */
export function warmTicket(): void {
  if (!cur || Date.now() - cur.at > REFRESH_MS) fresh().catch(() => {});
}

/** POSTs JSON with a valid ticket (and the honeypot value). Retries once if the ticket went stale. */
export async function postWithTicket(
  url: string,
  body: Record<string, unknown>,
  website: string,
): Promise<Response> {
  for (let attempt = 0; ; attempt++) {
    if (!cur || Date.now() - cur.at > REFRESH_MS) await fresh();
    const used = cur!;
    cur = null; // spent whatever happens: the server accepts a ticket once
    const age = Date.now() - used.at;
    if (age < WAIT_MS) await sleep(WAIT_MS - age);
    const res = await fetch(site(url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...body, ticket: used.ticket, website }),
    });
    if (res.status !== 428 || attempt > 0) {
      warmTicket(); // ready for whatever the person does next
      return res;
    }
  }
}

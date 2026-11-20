// Browser only. Fetches the shared inbox of locked private replies. Every visitor's browser calls this on a timer
// (components/InboxCover.tsx), whether or not they have written anything, so fetching it says nothing about anyone.
// Nothing is stored: the replies are kept in memory for this page only.

import { site } from "./site";

export interface InboxMessage {
  id: number;
  uid: string;
  blob: string;
  at: number;
}

let held: InboxMessage[] = [];
let cursor = 0;
let busy: Promise<InboxMessage[]> | null = null;

export function fetchInbox(): Promise<InboxMessage[]> {
  return (busy ??= (async () => {
    try {
      for (let i = 0; i < 20; i++) {
        const r = await fetch(site(`/api/inbox?after=${cursor}`), { cache: "no-store" });
        if (!r.ok) break;
        const d = (await r.json()) as { more: boolean; messages: InboxMessage[] };
        held = [...held, ...d.messages].slice(-5000);
        if (d.messages.length) cursor = d.messages[d.messages.length - 1].id;
        if (!d.more) break;
      }
    } catch {
      /* offline: try again next time */
    }
    busy = null;
    return held;
  })());
}

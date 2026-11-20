"use client";

import { useEffect } from "react";
import { fetchInbox } from "@/lib/inbox-client";

/**
 * Every page fetches the shared inbox now and then, so an author collecting their private replies looks exactly like
 * any reader. The first fetch waits a random moment, so page loads and fetches don't line up.
 */
export default function InboxCover() {
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const tick = () => {
      fetchInbox();
      timer = setTimeout(tick, 4 * 60_000 + Math.random() * 2 * 60_000);
    };
    timer = setTimeout(tick, 5_000 + Math.random() * 25_000);
    return () => clearTimeout(timer);
  }, []);
  return null;
}

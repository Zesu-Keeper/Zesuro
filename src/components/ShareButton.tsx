"use client";

import { useState } from "react";

/** Shares the entry's own page: the phone's share sheet where there is one, else copies the link. */
export default function ShareButton({ uid, title }: { uid: string; title: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");

  async function share() {
    const url = `${location.origin}/e/${uid}`;
    try {
      if (navigator.share) {
        await navigator.share({ title: title || "Zesuro", url });
        return;
      }
      await navigator.clipboard.writeText(url);
      setState("copied");
    } catch (e) {
      // Closing the share sheet is not an error.
      if (e instanceof DOMException && e.name === "AbortError") return;
      try {
        await navigator.clipboard.writeText(url);
        setState("copied");
      } catch {
        setState("failed");
        window.prompt("Copy this link", url);
      }
    }
    setTimeout(() => setState("idle"), 2000);
  }

  return (
    <button type="button" className="vote" onClick={share}>
      {state === "copied" ? "Link copied" : "Share"}
    </button>
  );
}

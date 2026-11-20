"use client";

import { useEffect } from "react";

// Like the exit button on domestic-abuse support sites: one press (or Esc twice) swaps this page for an ordinary
// one, without leaving this page as the previous step in the back button.
const ELSEWHERE = "https://www.google.com/search?q=weather+today";

function leave() {
  try {
    sessionStorage.clear();
  } catch {
    /* nothing kept */
  }
  window.location.replace(ELSEWHERE);
}

export default function LeaveQuickly() {
  useEffect(() => {
    let last = 0;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      const now = Date.now();
      if (now - last < 1500) leave();
      last = now;
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <button type="button" className="leave-quickly" onClick={leave} title="Leave this site now (or press Esc twice)">
      Leave quickly
    </button>
  );
}

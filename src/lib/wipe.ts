// Browser only. Clears what Zesuro has saved in this browser.
//   "chats": the private chats (their keys and any links not yet used), plus cached copies of the site.
//   "all":   everything Zesuro saved here, including the keys to your own posts.

import { chatStore } from "./chat-store";

export type WipeScope = "chats" | "all";

export async function wipeBrowser(scope: WipeScope): Promise<void> {
  try {
    if (scope === "all") localStorage.clear();
    else chatStore().wipeChats();
  } catch {
    /* storage blocked: nothing was kept */
  }
  try {
    sessionStorage.clear();
    if (scope === "all") chatStore().reload();
  } catch {
    /* nothing to clear */
  }
  try {
    if (scope === "all" && typeof indexedDB !== "undefined" && indexedDB.databases)
      for (const d of await indexedDB.databases()) if (d.name) indexedDB.deleteDatabase(d.name);
  } catch {
    /* none */
  }
  try {
    if (typeof caches !== "undefined") for (const k of await caches.keys()) await caches.delete(k);
  } catch {
    /* none */
  }
  try {
    if (scope === "all" && navigator.serviceWorker)
      for (const r of await navigator.serviceWorker.getRegistrations()) await r.unregister();
  } catch {
    /* none */
  }
  // Ask the browser to drop its own saved copies of this site as well (supported by Chrome, Edge and Firefox).
  try {
    await fetch(`/api/wipe?scope=${scope === "all" ? "all" : "cache"}`, { cache: "no-store" });
  } catch {
    /* offline: the steps above already ran */
  }
}

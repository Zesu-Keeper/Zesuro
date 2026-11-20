"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import Link from "next/link";
import Stamp from "./Stamp";
import {
  acceptJoin,
  inviteFragment,
  inviteIdOf,
  joinWith,
  MAX_TEXT,
  newInvite,
  parseInviteFragment,
  proofMatches,
  pseudonymOf,
  roomKeys,
  signIdentity,
  signProof,
  verifyIdentity,
  verifyProofSig,
  chatIdentity,
  MAX_USES,
  TIMER_CHOICES,
  type Body,
  type RoomKeys,
} from "@/lib/chat-crypto";
import {
  addInvite,
  addRoom,
  chatStore,
  dropInvite,
  dropRoom,
  eraseInviteKey,
  findRoom,
  loadChats,
  patchRoom,
  type StoredInvite,
  type StoredRoom,
} from "@/lib/chat-store";
import {
  b64uToBytes,
  deriveSaltV2,
  entryKey,
  entryKeysSupported,
  getOrCreateKey,
  loadMine,
  type MineEntry,
} from "@/lib/client-crypto";
import { ensureHello, loadSnapshot, pollRoom, sendMessage, startRoom, type Item } from "@/lib/chat-session";
import type { CommitContent } from "@/lib/commit";
import { postWithTicket, warmTicket } from "@/lib/ticket-client";
import { wipeBrowser } from "@/lib/wipe";
import { randomChatOrigin } from "@/lib/chat-hosts";

type Route = { view: "home" } | { view: "join"; secret: string } | { view: "room"; id: string };

function readRoute(): Route {
  const h = location.hash;
  const secret = parseInviteFragment(h);
  if (secret) return { view: "join", secret };
  const m = /^#r=([0-9a-f-]{36})$/.exec(h);
  if (m) return { view: "room", id: m[1] };
  return { view: "home" };
}

/** True on a private chat address: nothing there may say what site this is. */
const OnChatHost = createContext(false);
/** The path the chat is served from: "/" on a private address, "/chat" on the main site. */
const chatPath = () => (location.pathname === "/" ? "/" : "/chat");

function go(hash: string) {
  // replaceState keeps link secrets out of the back button's history.
  const base = chatPath();
  history.replaceState(null, "", hash ? `${base}#${hash}` : base);
  window.dispatchEvent(new HashChangeEvent("hashchange"));
}

const errText = (e: unknown, fallback: string) => (e instanceof Error && e.message ? e.message : fallback);

async function copyText(text: string, label: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    window.prompt(label, text);
    return false;
  }
}

/**
 * Every poll happens at this fixed interval, whether or not the tab is in view or anything
 * is going on, so the pattern of requests says nothing about when the person is there.
 */
const POLL_MS = 5_000;

const TIMERS: [number, string][] = [
  [0, "Keep messages"],
  [86_400_000, "Delete after 1 day"],
  [7 * 86_400_000, "Delete after 7 days"],
  [30 * 86_400_000, "Delete after 30 days"],
];
const timerLabel = (ttl: number) => TIMERS.find(([v]) => v === ttl)?.[1] ?? "Keep messages";

function useLocked(): boolean {
  return useSyncExternalStore(
    (f) => chatStore().subscribe(f),
    () => chatStore().isLocked(),
    () => false,
  );
}

export default function ChatApp({ apexes = [], onChatHost = false }: { apexes?: string[]; onChatHost?: boolean }) {
  const [route, setRoute] = useState<Route | null>(null);
  const locked = useLocked();
  useEffect(() => {
    const on = () => setRoute(readRoute());
    on();
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);

  // With a passcode set, the chats lock again after a while without use.
  useEffect(() => {
    if (locked) return;
    let last = Date.now();
    const touch = () => (last = Date.now());
    const events = ["pointerdown", "keydown", "touchstart", "scroll", "mousemove"] as const;
    for (const e of events) window.addEventListener(e, touch, { passive: true });
    const timer = setInterval(() => {
      const mins = chatStore().autoLockMinutes();
      if (mins > 0 && Date.now() - last >= mins * 60_000) chatStore().lockNow();
    }, 5_000);
    return () => {
      clearInterval(timer);
      for (const e of events) window.removeEventListener(e, touch);
    };
  }, [locked]);

  if (!route) return <p className="empty">Loading…</p>;
  if (typeof crypto === "undefined" || !crypto.subtle)
    return <p className="err">This browser can&apos;t do the encryption private chats need.</p>;
  const page = locked ? (
    <LockScreen />
  ) : route.view === "join" ? (
    <Join secret={route.secret} />
  ) : route.view === "room" ? (
    <Room key={route.id} id={route.id} />
  ) : (
    <Home apexes={apexes} />
  );
  return <OnChatHost.Provider value={onChatHost}>{page}</OnChatHost.Provider>;
}

// ------------------------------------------------------------------------------------------
// Lock screen
// ------------------------------------------------------------------------------------------

function LockScreen() {
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function open(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      if (!(await chatStore().unlock(pass))) setErr("That passcode isn't right.");
      else setPass("");
    } finally {
      setBusy(false);
    }
  }

  async function forgot() {
    if (
      !window.confirm(
        "Erase all your chats?\n\nWithout the passcode, the chats on this device can't be opened. This erases them and removes the passcode, so you can start fresh. It can't be undone.",
      )
    )
      return;
    await wipeBrowser("chats");
    chatStore().eraseEverything();
  }

  return (
    <main>
      <h1>Private chat</h1>
      <form className="card" onSubmit={open}>
        <p className="lede">Your chats are locked. Enter your passcode to open them.</p>
        <label className="lbl" htmlFor="chat-pass">Passcode</label>
        <input
          id="chat-pass"
          type="password"
          autoComplete="off"
          value={pass}
          onChange={(e) => setPass(e.target.value)}
          autoFocus
        />
        {err ? <p className="err">{err}</p> : null}
        <div className="row" style={{ justifyContent: "flex-start" }}>
          <button type="submit" className="primary" disabled={busy || !pass}>
            {busy ? "Unlocking…" : "Unlock"}
          </button>
        </div>
        <p className="count">
          Forgot it? There is no way to recover the chats without it.{" "}
          <button type="button" className="link" onClick={forgot}>Erase my chats and start again</button>
        </p>
      </form>
    </main>
  );
}

// ------------------------------------------------------------------------------------------
// Passcode and auto-lock settings
// ------------------------------------------------------------------------------------------

function Security() {
  const [on, setOn] = useState(false);
  const [mins, setMins] = useState(5);
  const [pass, setPass] = useState("");
  const [again, setAgain] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const st = chatStore();
    setOn(st.lockConfigured());
    if (st.autoLockMinutes()) setMins(st.autoLockMinutes());
  }, []);

  async function save() {
    setErr(null);
    setMsg(null);
    if (pass.length < 8) return setErr("Use at least 8 characters.");
    if (pass !== again) return setErr("The two passcodes don't match.");
    setBusy(true);
    try {
      if (!(await chatStore().setPasscode(pass, mins))) throw new Error("Could not set the passcode.");
      setOn(true);
      setPass("");
      setAgain("");
      setMsg("Done. Your chats are now locked with this passcode.");
    } catch (e) {
      setErr(errText(e, "Could not set the passcode."));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setErr(null);
    setMsg(null);
    const typed = window.prompt("Enter your passcode to remove it:");
    if (!typed) return;
    setBusy(true);
    try {
      if (!(await chatStore().removePasscode(typed))) return setErr("That passcode isn't right.");
      setOn(false);
      setMsg("The passcode was removed. Your chats are stored on this device without a lock.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <details>
      <summary>Lock my chats with a passcode</summary>
      <p className="count">
        With a passcode, everything chat-related on this device (chat keys, links and message history) is
        scrambled with a key made from it. Nobody who picks up the device can read the chats without it.
        The chats lock themselves after a few quiet minutes. If you forget the passcode, nobody can open
        them, including us.
      </p>
      {on ? (
        <>
          <div className="row" style={{ justifyContent: "flex-start" }}>
            <button type="button" className="primary" onClick={() => chatStore().lockNow()}>Lock now</button>
            <label className="count">
              Lock after{" "}
              <select
                value={mins}
                onChange={(e) => {
                  setMins(Number(e.target.value));
                  chatStore().setAutoLockMinutes(Number(e.target.value));
                }}
                aria-label="Lock after"
              >
                {[1, 2, 5, 15, 30].map((m) => (
                  <option key={m} value={m}>{m} {m === 1 ? "minute" : "minutes"}</option>
                ))}
              </select>{" "}
              without use
            </label>
          </div>
          <p className="count">To change the passcode, remove it and set a new one.</p>
          <button type="button" className="link" onClick={remove} disabled={busy}>Remove the passcode</button>
        </>
      ) : (
        <>
          <label className="lbl" htmlFor="new-pass">New passcode (at least 8 characters)</label>
          <input id="new-pass" type="password" autoComplete="new-password" value={pass} onChange={(e) => setPass(e.target.value)} />
          <label className="lbl" htmlFor="new-pass2">Type it again</label>
          <input id="new-pass2" type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} />
          <label className="lbl" htmlFor="lock-mins">Lock after</label>
          <select id="lock-mins" value={mins} onChange={(e) => setMins(Number(e.target.value))}>
            {[1, 2, 5, 15, 30].map((m) => (
              <option key={m} value={m}>{m} {m === 1 ? "minute" : "minutes"} without use</option>
            ))}
          </select>
          <div className="row" style={{ justifyContent: "flex-start" }}>
            <button type="button" className="primary" onClick={save} disabled={busy || !pass}>
              {busy ? "Locking…" : "Lock my chats"}
            </button>
          </div>
        </>
      )}
      {err ? <p className="err">{err}</p> : null}
      {msg ? <p className="notice">{msg}</p> : null}
    </details>
  );
}

// ------------------------------------------------------------------------------------------
// Home: start a chat, see links and chats
// ------------------------------------------------------------------------------------------

function Home({ apexes }: { apexes: string[] }) {
  const onChat = useContext(OnChatHost);
  const [invites, setInvites] = useState<StoredInvite[]>([]);
  const [rooms, setRooms] = useState<StoredRoom[]>([]);
  const [uses, setUses] = useState<Record<string, number>>({});
  const [mode, setMode] = useState<"once" | "some" | "any">("once");
  const [count, setCount] = useState(3);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [fresh, setFresh] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [trap, setTrap] = useState("");
  const [keepTab, setKeepTab] = useState(false);

  const reload = useCallback(() => {
    const s = loadChats();
    setInvites(s.invites);
    setRooms(s.rooms);
  }, []);

  useEffect(() => {
    reload();
    warmTicket();
    setKeepTab(chatStore().keepMode() === "session");
  }, [reload]);

  // A chat the other person ended: its key is deleted from this browser as soon as we notice.
  useEffect(() => {
    let stop = false;
    async function sweep() {
      let ended = 0;
      for (const r of loadChats().rooms.slice(0, 20)) {
        try {
          const k = await roomKeys(r.master, r.id);
          const res = await fetch(`/api/chat/rooms/${r.id}?after=2147483647`, { cache: "no-store", headers: { "x-chat-auth": k.token } });
          if (res.status === 410) {
            dropRoom(r.id);
            ended++;
          }
        } catch {
          /* offline: try again later */
        }
      }
      if (stop || !ended) return;
      setNote(
        ended === 1
          ? "A chat was ended by the other person. Its key has been deleted from this browser."
          : `${ended} chats were ended by the other person. Their keys have been deleted from this browser.`,
      );
      reload();
    }
    sweep();
    const t = setInterval(sweep, 60_000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, [reload]);

  // Watch the links this browser made: when someone opens one, finish the key exchange.
  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    async function tick() {
      for (const inv of loadChats().invites) {
        try {
          const r = await fetch(`/api/chat/invites/${inv.id}`, {
            cache: "no-store",
            headers: { "x-chat-owner": inv.ownerSecret },
          });
          if (!r.ok) continue;
          const st = (await r.json()) as {
            uses: number;
            open: boolean;
            rooms: { id: string; join: string; slot: number; createdAt: number; deleted: boolean }[];
          };
          // Never accept more people than the link allows, whatever the server says.
          const allowed = st.rooms.slice(0, inv.maxUses > 0 ? inv.maxUses : MAX_USES);
          let refused = 0;
          for (const room of allowed) {
            if (room.deleted || findRoom(room.id)) continue;
            const got = await acceptJoin(inv.secret, inv.privs?.[room.slot] ?? null, room.id, room.join, room.slot);
            if (got) {
              const mine: StoredRoom = { id: room.id, role: "a", master: got.master, createdAt: room.createdAt, via: inv.id, v: 2, ...(inv.mem ? { mem: true } : {}) };
              // The chat's first secret state is written before the room is listed, so it can never exist without it.
              if (!(await startRoom(mine, { kind: "creator", theirPub: got.theirPub })) || !addRoom(mine)) continue;
              // The key for this chat is no longer needed, and nothing may be able to re-derive it.
              eraseInviteKey(inv.id, room.slot);
              // Say a first hello now if we can, so the other person can reply straight away.
              roomKeys(got.master, room.id).then((k) => ensureHello(mine, k)).catch(() => {});
            } else refused++;
          }
          if (stop) return;
          if (refused)
            setNote(
              "Someone used one of your links without holding the real link, so no chat was started with them. If the person you sent it to can't get in, make a new link.",
            );
          setUses((u) => (u[inv.id] === st.uses ? u : { ...u, [inv.id]: st.uses }));
          // A used-up link's private key is no longer needed: destroy it.
          if (!st.open) dropInvite(inv.id);
        } catch {
          /* offline: try again next time */
        }
      }
      if (stop) return;
      reload();
      timer = setTimeout(tick, POLL_MS);
    }
    tick();
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  }, [reload]);

  async function create() {
    setErr(null);
    setNote(null);
    setBusy(true);
    try {
      const maxUses = mode === "once" ? 1 : mode === "any" ? 0 : Math.min(Math.max(Math.floor(count) || 2, 2), MAX_USES);
      // The device secret that chat identities and entry keys come from is made the first time it is needed.
      await getOrCreateKey();
      const inv = await newInvite(maxUses);
      const res = await postWithTicket(
        "/api/chat/invites",
        { id: inv.id, owner: inv.ownerHash, hello: inv.hello, maxUses },
        trap,
      );
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Could not create the link");
      const ok = addInvite({
        secret: inv.secret,
        id: inv.id,
        ownerSecret: inv.ownerSecret,
        privs: inv.privs,
        maxUses,
        createdAt: Date.now(),
        ...(keepTab ? { mem: true } : {}),
      });
      if (!ok) throw new Error("This browser is not letting the site store the chat key. Private windows and blocked storage won't work.");
      setFresh(inv.id);
      reload();
    } catch (e) {
      setErr(errText(e, "Could not create the link"));
    } finally {
      setBusy(false);
    }
  }

  async function cancel(inv: StoredInvite) {
    if (!window.confirm("Cancel this link? Nobody else will be able to open it. Chats already started carry on.")) return;
    try {
      await fetch(`/api/chat/invites/${inv.id}`, { method: "DELETE", headers: { "x-chat-owner": inv.ownerSecret } });
    } catch {
      /* the local copy goes either way */
    }
    dropInvite(inv.id);
    reload();
  }

  const linkOf = (inv: StoredInvite) => `${location.origin}${chatPath()}#${inviteFragment(inv.secret)}`;

  // The emergency button: end every chat for both people, cancel unused links, then erase this browser's copies.
  async function endAllAndErase() {
    if (
      !window.confirm(
        "End every chat and erase everything?\n\nEvery chat is ended for both of you and its messages are deleted from this site. Links you haven't used are cancelled. This browser forgets all of its chat keys and saved copies of the site. Your post keys are not touched. This can't be undone.",
      )
    )
      return;
    setBusy(true);
    const s = loadChats();
    for (const r of s.rooms) {
      try {
        const k = await roomKeys(r.master, r.id);
        await fetch(`/api/chat/rooms/${r.id}`, { method: "DELETE", headers: { "x-chat-auth": k.token } });
      } catch {
        /* offline: the local keys are still erased below */
      }
    }
    for (const inv of s.invites) {
      try {
        await fetch(`/api/chat/invites/${inv.id}`, { method: "DELETE", headers: { "x-chat-owner": inv.ownerSecret } });
      } catch {
        /* same */
      }
    }
    await wipeBrowser("chats");
    reload();
    setBusy(false);
    setNote("Done. Every chat was ended and this browser has forgotten them.");
  }

  async function eraseChatsHere() {
    if (
      !window.confirm(
        "Erase your chats from this browser only?\n\nYou won't be able to read them here again. The chats stay on the site for the other person, and nothing is deleted from the site.",
      )
    )
      return;
    await wipeBrowser("chats");
    reload();
    setNote("Done. This browser has forgotten its chats.");
  }

  async function eraseEverything() {
    if (
      !window.confirm(
        (onChat
          ? "Erase everything saved in this browser for this address?\n\nChats are not ended for the other person. This can't be undone."
          : "Erase everything Zesuro saved in this browser?\n\nThis also deletes the keys to your own posts. Unless you saved a backup of your key, you will never be able to reveal them. Chats are not ended for the other person. This can't be undone."),
      )
    )
      return;
    await wipeBrowser("all");
    window.location.href = "/";
  }

  return (
    <main>
      <h1>Private chat</h1>
      <p className="lede">
        Chat privately with one person. Your messages are scrambled on your device before they are
        sent, so this site can&apos;t read them. Every message gets its own key, and the key is
        erased as soon as it has been used, so even a stolen device or key can&apos;t open messages
        that were already sent. To start, make a link and send it to the person you want to talk to.
      </p>

      {!onChat && apexes.length ? (
        <div className="card">
          <h2 className="title">Want nothing in your browser to point to this site?</h2>
          <p className="count">
            Start the chat on a random private address instead. Your browser will only ever show that
            address, which doesn&apos;t mention this site, so nothing it keeps can be linked back here. The trade-off:
            you can&apos;t show the other person that you wrote a public post there, because your post keys
            stay on this site.
          </p>
          <div className="row" style={{ justifyContent: "flex-start" }}>
            <button
              type="button"
              className="primary"
              onClick={() => {
                const to = randomChatOrigin(apexes);
                if (to) window.location.href = `${to}/`;
              }}
            >
              Open a private address
            </button>
          </div>
        </div>
      ) : null}

      <div className="card">
        <h2 className="title">Start a private chat</h2>
        <fieldset className="chat-opts">
          <legend className="lbl">How many times can the link be opened?</legend>
          <label className="opt">
            <input type="radio" name="uses" checked={mode === "once"} onChange={() => setMode("once")} />
            <span>
              Once <small>Safest. If someone else opens it first, the person you meant it for is told it was already used.</small>
            </span>
          </label>
          <label className="opt">
            <input type="radio" name="uses" checked={mode === "some"} onChange={() => setMode("some")} />
            <span>
              A set number of times{" "}
              <input
                type="number"
                min={2}
                max={100}
                value={count}
                onChange={(e) => setCount(Number(e.target.value))}
                onFocus={() => setMode("some")}
                aria-label="Number of times"
                className="chat-num"
              />
              <small>Each person who opens it gets their own separate chat with you.</small>
            </span>
          </label>
          <label className="opt">
            <input type="radio" name="uses" checked={mode === "any"} onChange={() => setMode("any")} />
            <span>
              Up to 100 people <small>Anyone who ever sees the link can start a chat with you until 100 have. Least safe.</small>
            </span>
          </label>
        </fieldset>
        <input
          className="trap"
          type="text"
          name="website"
          tabIndex={-1}
          autoComplete="off"
          aria-hidden="true"
          value={trap}
          onChange={(e) => setTrap(e.target.value)}
        />
        <label className="opt">
          <input
            type="checkbox"
            checked={keepTab}
            onChange={(e) => {
              setKeepTab(e.target.checked);
              chatStore().setKeepMode(e.target.checked ? "session" : "device");
            }}
          />
          <b>Only keep this chat until I close this tab</b>
          <small>
            Nothing is saved on this device. When you close the tab the chat is gone for you, and you
            can&apos;t come back to it. Keep this page open until the other person has joined.
          </small>
        </label>
        <div className="row" style={{ justifyContent: "flex-start" }}>
          <button type="button" className="primary" onClick={create} disabled={busy}>
            {busy ? "Making the link…" : "Make a chat link"}
          </button>
        </div>
        {err ? <p className="err">{err}</p> : null}
        {note ? <p className="notice">{note}</p> : null}
      </div>

      <p className="count">
        The other person never sees your name, your address or an account. If you started the chat,
        they only see a made-up name that exists for this chat alone.
        {onChat ? null : (
          <>
            {" "}Later you can choose to show them that you wrote a particular public post, without
            saying who you are. <Link href="/mine">Back up your key</Link> so you can still do that from
            another device.
          </>
        )}
      </p>

      {invites.length ? <h2 className="chat-h">Links waiting to be opened</h2> : null}
      {invites.map((inv) => (
        <div className={`card${fresh === inv.id ? " chat-fresh" : ""}`} key={inv.id}>
          <div className="meta" style={{ marginTop: 0 }}>
            <span>Made <Stamp ms={inv.createdAt} /></span>
            <span>
              Opened {uses[inv.id] ?? 0} of {inv.maxUses === 0 ? "unlimited" : inv.maxUses}
            </span>
          </div>
          <input type="text" readOnly value={linkOf(inv)} aria-label="Chat link" onFocus={(e) => e.currentTarget.select()} />
          <div className="row">
            <button
              type="button"
              onClick={async () => {
                if (await copyText(linkOf(inv), "Copy this chat link")) {
                  setCopied(inv.id);
                  setTimeout(() => setCopied(null), 2000);
                }
              }}
            >
              {copied === inv.id ? "Copied" : "Copy link"}
            </button>
            <button type="button" className="link" onClick={() => cancel(inv)}>
              Cancel link
            </button>
          </div>
          {fresh === inv.id ? (
            <div className="warnbox">
              Be careful how you send this link. Whoever opens it first becomes the other person in
              the chat, and if you send it from an account with your real name, they will know who
              you are. Keep this page open, or come back to it in this same browser: the chat will
              show up here once the link is opened.
            </div>
          ) : null}
        </div>
      ))}

      <h2 className="chat-h">Your chats</h2>
      {rooms.length === 0 ? <p className="empty">No chats in this browser yet.</p> : null}
      {rooms.map((r) => (
        <div className="card" key={r.id}>
          <div className="row" style={{ marginTop: 0 }}>
            <span>
              <span className={`badge ${r.role === "a" ? "revealed" : "anonymous"}`}>
                {r.role === "a" ? "You made the link" : "You opened a link"}
              </span>{" "}
              <span className="count">Started <Stamp ms={r.createdAt} /></span>
            </span>
            <button type="button" className="primary" onClick={() => go(`r=${r.id}`)}>
              Open
            </button>
          </div>
        </div>
      ))}

      <p className="count">
        A chat only opens in the browser that started or joined it, and can&apos;t be moved to
        another device. That is what keeps it safe.
      </p>

      <Security />

      <details>
        <summary>Erase chats from this browser</summary>
        <p className="count">
          Use this if someone else might get hold of this device, or when you&apos;re finished.
        </p>
        <div className="row" style={{ justifyContent: "flex-start" }}>
          <button type="button" className="danger" onClick={endAllAndErase} disabled={busy}>
            End all my chats and erase them
          </button>
        </div>
        <p className="count">
          Ends every chat for both people and deletes the messages from this site. Cancels links you
          haven&apos;t used. Then this browser forgets the chat keys and clears its saved copies of the site.
        </p>
        <div className="row" style={{ justifyContent: "flex-start" }}>
          <button type="button" onClick={eraseChatsHere}>Only erase them from this browser</button>
        </div>
        <p className="count">The chats stay on the site for the other person. You just can&apos;t read them here again.</p>
        <div className="row" style={{ justifyContent: "flex-start" }}>
          <button type="button" onClick={eraseEverything}>
            {onChat ? "Erase everything saved here" : "Erase everything Zesuro saved in this browser"}
          </button>
        </div>
        {onChat ? null : (
          <p className="count">
            This also deletes the keys to your own posts, so only do it if you have a backup of your key.
          </p>
        )}
        <p className="count">
          Erasing can&apos;t clear your browser&apos;s history (the address of a chat link may still be
          listed there), files you saved such as transcripts, or screenshots. For the fewest traces, open
          chats in a private window or in Tor Browser, and close it when you&apos;re done.
        </p>
      </details>

      <details>
        <summary>What this does and doesn&apos;t protect</summary>
        <ul className="chat-notes">
          <li>This site can&apos;t read your messages. It also can&apos;t tell which public posts a chat is about, unless you choose to prove one.</li>
          <li>Each message is locked with its own key, which is erased after it is used. If someone steals your device or a key later, they can&apos;t open messages that were already sent. A message you have already read stays on this device, so end the chat or use the delete timer to remove it.</li>
          <li>A chat lives only on the device that started it. It can&apos;t be copied to another device, because that would break the key swapping that keeps it safe.</li>
          <li>The site can see the internet address your browser connects from, but it doesn&apos;t keep a record of it. Use Tor Browser to hide that too.</li>
          <li>Anyone who can use your unlocked phone or computer can read your chats. Use the delete timer or &quot;End chat and delete keys&quot; if that worries you.</li>
          <li>Deleting removes the messages from this site. It can&apos;t remove a copy the other person saved or took a photo of. Scrambled copies can stay in the site&apos;s backups for up to 14 days.</li>
          <li>If you can, compare the safety code with the other person. If the codes match, nobody is listening in the middle.</li>
        </ul>
        {onChat ? null : (
          <p className="count">
            More in the <Link href="/help#private-chat">help guide</Link>.
          </p>
        )}
      </details>
    </main>
  );
}

// ------------------------------------------------------------------------------------------
// Join: someone opened a link
// ------------------------------------------------------------------------------------------

function Join({ secret }: { secret: string }) {
  const [state, setState] = useState<"checking" | "ready" | "used" | "own" | "invalid" | "busy">("checking");
  const [err, setErr] = useState<string | null>(null);
  const hello = useRef<string>("");
  const slot = useRef<number>(0);
  const [keepTab, setKeepTab] = useState(false);
  useEffect(() => {
    setKeepTab(chatStore().keepMode() === "session");
  }, []);

  useEffect(() => {
    let off = false;
    (async () => {
      try {
        const id = await inviteIdOf(secret);
        const s = loadChats();
        const mine = s.rooms.find((r) => r.via === id && r.role === "b");
        if (mine) return go(`r=${mine.id}`);
        if (s.invites.some((i) => i.id === id)) return setState("own");
        const r = await fetch(`/api/chat/invites/${id}`, { cache: "no-store" });
        if (off) return;
        if (r.status === 404) return setState("invalid");
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || "Could not check the link");
        hello.current = d.hello;
        slot.current = d.slot;
        setState(d.open ? "ready" : "used");
      } catch (e) {
        if (!off) {
          setErr(errText(e, "Could not check the link"));
          setState("invalid");
        }
      }
    })();
    return () => {
      off = true;
    };
  }, [secret]);

  async function join() {
    setErr(null);
    setState("busy");
    try {
      const id = await inviteIdOf(secret);
      for (let attempt = 0; ; attempt++) {
        const j = await joinWith(secret, hello.current, slot.current);
        // Store the key before using up the link, so a refused write can't strand the chat.
        const mine: StoredRoom = { id: j.roomId, role: "b", master: j.master, createdAt: Date.now(), via: id, v: 2, ...(keepTab ? { mem: true } : {}) };
        if (
          !(await startRoom(mine, { kind: "opener", priv: j.ratchetPriv, pub: j.ratchetPub })) ||
          !addRoom(mine)
        )
          throw new Error("This browser is not letting the site store the chat key. Private windows and blocked storage won't work.");
        const res = await fetch(`/api/chat/invites/${id}/join`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ room: j.roomId, join: j.join, auth: j.authHash, slot: slot.current }),
        });
        if (res.ok) {
          go(`r=${j.roomId}`);
          return;
        }
        dropRoom(j.roomId);
        if (res.status === 410) return setState("used");
        if (res.status === 409 && attempt < 4) {
          // Someone else opened a multi-use link at the same moment: take the next free place.
          const f = await fetch(`/api/chat/invites/${id}`, { cache: "no-store" });
          const d = await f.json().catch(() => null);
          if (f.ok && d?.open) {
            hello.current = d.hello;
            slot.current = d.slot;
            continue;
          }
          return setState("used");
        }
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || "Could not open the chat");
      }
    } catch (e) {
      setErr(errText(e, "Could not open the chat"));
      setState("ready");
    }
  }

  return (
    <main>
      <h1>Private chat</h1>
      {state === "checking" ? <p className="empty">Checking the link…</p> : null}
      {state === "ready" || state === "busy" ? (
        <div className="card">
          <p className="lede">
            Someone has invited you to a private chat. Your messages are scrambled on your device
            before they are sent, so this site can&apos;t read them.
          </p>
          <ul className="chat-notes">
            <li>Open it in the browser you plan to keep using. The chat key is kept in this browser, and the link may only work once.</li>
            <li>You don&apos;t need an account. The other person learns nothing about you except what you type.</li>
            <li>The other person can show you that they wrote a particular public post, without telling you who they are.</li>
          </ul>
          <label className="opt">
            <input
              type="checkbox"
              checked={keepTab}
              onChange={(e) => {
                setKeepTab(e.target.checked);
                chatStore().setKeepMode(e.target.checked ? "session" : "device");
              }}
            />
            <b>Only keep this chat until I close this tab</b>
            <small>Nothing is saved on this device. When you close the tab, the chat is gone for you.</small>
          </label>
          <div className="row" style={{ justifyContent: "flex-start" }}>
            <button type="button" className="primary" onClick={join} disabled={state === "busy"}>
              {state === "busy" ? "Opening…" : "Open the chat"}
            </button>
          </div>
        </div>
      ) : null}
      {state === "used" ? (
        <div className="warnbox">
          <b>This link has already been used, or was cancelled.</b> If you didn&apos;t open it yourself
          (maybe in another browser), someone else may have. Tell the person who sent it, using a
          different way of getting in touch, and ask for a new link. If you did open it before, go
          back to the browser you used. The chat will be under <Link href="/chat">Private chat</Link> there.
        </div>
      ) : null}
      {state === "own" ? (
        <div className="notice">
          This is a link you made in this browser. Send it to the other person; the chat will appear
          under <button type="button" className="link" onClick={() => go("")}>your chats</button> once they open it.
        </div>
      ) : null}
      {state === "invalid" ? <p className="err">{err || "This chat link is not valid."}</p> : null}
      {state !== "invalid" && err ? <p className="err">{err}</p> : null}
    </main>
  );
}

// ------------------------------------------------------------------------------------------
// Room
// ------------------------------------------------------------------------------------------

type ProofState = { status: "checking" | "ok" | "bad" | "gone"; title?: string; createdAt?: number };

function Room({ id }: { id: string }) {
  const onChat = useContext(OnChatHost);
  const [room] = useState<StoredRoom | null>(() => findRoom(id));
  const [keys, setKeys] = useState<RoomKeys | null>(null);
  const [items, setItems] = useState<Item[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [canSend, setCanSend] = useState(true);
  const [ttl, setTtl] = useState(0);
  const [gone, setGone] = useState<"deleted" | "missing" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [source, setSource] = useState<{ id: string } | null>(null);
  const [me, setMe] = useState<string | null>(null);
  const [introducing, setIntroducing] = useState(false);
  const [badId, setBadId] = useState(false);
  const [proofs, setProofs] = useState<Record<number, ProofState>>({});
  const [mine, setMine] = useState<MineEntry[]>([]);
  const [pick, setPick] = useState("");

  const polling = useRef(false);
  const checkedProofs = useRef(new Set<number>());
  const hadTimer = useRef(room?.hadTimer ?? false);
  const bottom = useRef<HTMLDivElement>(null);
  const role = room?.role ?? "b";
  const legacy = !!room && room.v !== 2;

  useEffect(() => {
    if (!room) return;
    roomKeys(room.master, room.id).then(setKeys).catch(() => setErr("This chat's key is damaged."));
    if (room.role === "a") {
      setMine(loadMine());
      getOrCreateKey()
        .then((k) => chatIdentity(b64uToBytes(k.priv.d!), room.id))
        .then((i) => pseudonymOf(i.pubX))
        .then(setMe)
        .catch(() => {});
    }
  }, [room]);

  // What is already kept on this device shows straight away, before the site is asked.
  useEffect(() => {
    if (!room || legacy) return;
    let off = false;
    loadSnapshot(room).then((snap) => {
      if (off || !snap) return;
      setItems(snap.items);
      setCanSend(snap.canSend);
    });
    return () => {
      off = true;
    };
  }, [room, legacy]);

  // The other person ended the chat: erase this browser's key and what is on screen straight away.
  useEffect(() => {
    if (gone !== "deleted" || !room) return;
    dropRoom(room.id);
    setItems([]);
    setKeys(null);
  }, [gone, room]);

  const poll = useCallback(async () => {
    if (!keys || !room || room.v !== 2 || polling.current) return;
    polling.current = true;
    try {
      const snap = await pollRoom(room, keys);
      if (snap.gone) return setGone(snap.gone);
      setItems(snap.items);
      setCanSend(snap.canSend);
      setTtl(snap.ttl);
      setErr(null);
      setLoaded(true);
    } catch (e) {
      setErr(errText(e, "Could not reach the server"));
    } finally {
      polling.current = false;
    }
  }, [keys, room]);

  useEffect(() => {
    if (!keys || !room || room.v !== 2) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const loop = async () => {
      await poll();
      if (!stop) timer = setTimeout(loop, POLL_MS);
    };
    // The one who made the link says a first, invisible hello, so the other person can reply at once.
    ensureHello(room, keys).catch(() => {}).finally(() => !stop && loop());
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  }, [keys, room, poll]);

  // A delete timer has been on at some point, so earlier messages may legitimately be missing.
  useEffect(() => {
    if (!room || hadTimer.current) return;
    if (items.some((i) => i.msg?.kind === "timer" && i.msg.ttl > 0)) {
      hadTimer.current = true;
      patchRoom(room.id, { hadTimer: true });
    }
  }, [items, room]);

  const send = useCallback(
    async (body: Body) => {
      if (!keys || !room) return;
      const snap = await sendMessage(room, keys, body);
      setItems(snap.items);
      setCanSend(snap.canSend);
    },
    [keys, room],
  );

  const introduced = items.some((i) => i.msg?.from === "a" && i.msg.kind === "id");

  // The source introduces themselves only when they choose to, after comparing the safety code.
  async function introduce() {
    if (!keys || !room || room.role !== "a") return;
    setIntroducing(true);
    setErr(null);
    try {
      if (!(await entryKeysSupported())) throw new Error("This browser is too old to introduce you. Use a current Firefox, Chrome or Safari.");
      const k = await getOrCreateKey();
      const id = await chatIdentity(b64uToBytes(k.priv.d!), room.id);
      await send({ kind: "id", pub: id.pubX, sig: await signIdentity(id.sign, room.id, keys.bind) });
    } catch (e) {
      setErr(errText(e, "Could not introduce you"));
    } finally {
      setIntroducing(false);
    }
  }

  // Check the source's introduction, then each proof against the public record.
  useEffect(() => {
    if (!keys || !room) return;
    let off = false;
    (async () => {
      let src = source;
      if (!src) {
        let sawBad = false;
        for (const it of items) {
          const m = it.msg;
          if (m?.from !== "a" || m.kind !== "id") continue;
          if (await verifyIdentity(m.pub, m.sig, room.id, keys.bind)) {
            src = { id: await pseudonymOf(m.pub) };
            break;
          }
          sawBad = true;
        }
        if (off) return;
        if (src) setSource(src);
        else if (sawBad) setBadId(true);
      }
      for (const it of items) {
        const m = it.msg;
        if (m?.from !== "a" || m.kind !== "proof" || checkedProofs.current.has(it.id)) continue;
        let st: ProofState = { status: "gone" };
        try {
          const r = await fetch(`/api/entries/${encodeURIComponent(m.uid)}`, { cache: "no-store" });
          if (r.ok) {
            const e = (await r.json()).entry as CommitContent & { commitment: string; commitV: number; createdAt: number };
            const holds =
              e.commitV === 2 &&
              (await proofMatches(m.pub, m.salt, e, e.commitment)) &&
              (await verifyProofSig(m.pub, m.sig, room.id, keys.bind, m.uid));
            st = {
              status: holds ? "ok" : "bad",
              title: e.title || e.text.slice(0, 80),
              createdAt: e.createdAt,
            };
          }
        } catch {
          st = { status: "gone" };
        }
        if (off) return;
        checkedProofs.current.add(it.id);
        setProofs((p) => ({ ...p, [it.id]: st }));
      }
    })();
    return () => {
      off = true;
    };
  }, [items, keys, room, source]);

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: "nearest" });
  }, [items.length]);

  // Each sender numbers their messages. Anything missing, repeated or unreadable is flagged.
  const flags = useMemo(() => {
    const out: Record<number, string> = {};
    const next: Partial<Record<"a" | "b", number>> = {};
    for (const it of items) {
      const m = it.msg;
      if (!m) {
        out[it.id] = "This message couldn't be read. It may have been changed, or it didn't come from either of you.";
        continue;
      }
      const want = next[m.from];
      if (want === undefined) {
        if (m.n > 0 && !hadTimer.current) out[it.id] = "Earlier messages from this person are missing.";
      } else if (m.n > want) out[it.id] = "Some messages before this one are missing.";
      else if (m.n < want) out[it.id] = "This message is a repeat, or arrived out of order.";
      next[m.from] = Math.max(want ?? 0, m.n + 1);
    }
    return out;
  }, [items]);

  async function submit() {
    const t = text.replace(/\r\n?/g, "\n").trim();
    if (!t) return;
    setSending(true);
    setErr(null);
    try {
      await send({ kind: "text", text: t });
      setText("");
    } catch (e) {
      setErr(errText(e, "Could not send"));
    } finally {
      setSending(false);
    }
  }

  async function prove() {
    const e = mine.find((x) => x.uid === pick);
    if (!e || !keys || !room) return;
    setErr(null);
    try {
      if (!(await entryKeysSupported())) throw new Error("This browser is too old to make proofs. Use a current Firefox, Chrome or Safari.");
      const k = await getOrCreateKey();
      const ek = await entryKey(k, e.nonce);
      await send({
        kind: "proof",
        uid: e.uid,
        pub: ek.pubX,
        salt: await deriveSaltV2(k, e.nonce),
        sig: await signProof(ek.sign, room.id, keys.bind, e.uid),
      });
      setPick("");
    } catch (x) {
      setErr(errText(x, "Could not send the proof"));
    }
  }

  async function changeTimer(v: number) {
    if (!keys || !room) return;
    setErr(null);
    try {
      const r = await fetch(`/api/chat/rooms/${room.id}`, {
        method: "PATCH",
        headers: { "content-type": "application/json", "x-chat-auth": keys.token },
        body: JSON.stringify({ ttl: v }),
      });
      if (!r.ok) throw new Error("Could not change the timer");
      setTtl(v);
      await send({ kind: "timer", ttl: v });
    } catch (e) {
      setErr(errText(e, "Could not change the timer"));
    }
  }

  /** Forget everything this page holds in memory about the chat. */
  function wipeScreen() {
    setItems([]);
    setKeys(null);
    setText("");
  }

  // Ends the chat for both people: every message is removed from this site and this browser's key is erased.
  // The other person's browser erases its key as soon as it next looks at the chat.
  async function endChat() {
    if (!room) return;
    if (
      !window.confirm(
        "End this chat and delete the keys?\n\nEvery message is removed from this site, and the key on this device is erased. The other person's key is erased as soon as their browser next checks the chat. Nobody will be able to read it again. This can't be undone.",
      )
    )
      return;
    try {
      if (keys) {
        const r = await fetch(`/api/chat/rooms/${room.id}`, { method: "DELETE", headers: { "x-chat-auth": keys.token } });
        if (!r.ok && r.status !== 410 && r.status !== 404) throw new Error("Could not end the chat");
      }
      wipeScreen();
      dropRoom(room.id);
      go("");
    } catch (e) {
      setErr(errText(e, "Could not end the chat. Nothing was deleted. Try again, or delete just this device's key."));
    }
  }

  // Deletes only this device's key. The chat stays on the site for the other person, but it can't be read here again.
  function forgetHere() {
    if (!room) return;
    if (
      !window.confirm(
        "Delete your key for this chat on this device?\n\nYou will not be able to read it here again. The other person's side is not changed. To end it for both of you, use \"End chat and delete keys\".",
      )
    )
      return;
    wipeScreen();
    dropRoom(room.id);
    go("");
  }

  function saveTranscript() {
    if (!room) return;
    const who = (f: "a" | "b") => (f === "a" ? "SOURCE" : "CONTACT");
    const lines = [
      onChat ? "Private chat transcript" : "Zesuro private chat transcript",
      `Chat ${room.id}`,
      `Saved ${new Date().toISOString()}`,
      source ? `Source pseudonym in this chat ${source.id}` : "Source not introduced or not verified",
      "",
    ];
    for (const it of items) {
      const m = it.msg;
      if (!m) {
        lines.push(`[#${it.id}] UNREADABLE MESSAGE`);
        continue;
      }
      const head = `[${new Date(m.t).toISOString()}] ${who(m.from)} #${m.n}`;
      if (m.kind === "text") lines.push(`${head}: ${m.text}`);
      else if (m.kind === "proof") {
        const p = proofs[it.id];
        lines.push(
          `${head}: PROOF OF ENTRY ${location.origin}/e/${m.uid} entry-key=${m.pub} salt=${m.salt} result=${p?.status ?? "unchecked"}`,
          `    To check it yourself: SHA-256 of "zesuro:commit:v2:" + entry-key + ":" + salt + ":" + SHA-256(content) must equal the entry's public commitment (the entry page shows the content and its hash).`,
        );
      } else if (m.kind === "timer") lines.push(`${head}: set the timer to "${timerLabel(m.ttl)}"`);
      else if (m.kind === "id") lines.push(`${head}: introduced themselves (chat key ${m.pub}, signature ${m.sig})`);
      if (flags[it.id]) lines.push(`    WARNING: ${flags[it.id]}`);
    }
    const url = URL.createObjectURL(new Blob([lines.filter((l) => l !== "").join("\n") + "\n"], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${onChat ? "chat" : "zesuro-chat"}-${room.id.slice(0, 8)}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5_000);
  }

  if (!room)
    return (
      <main>
        <h1>Private chat</h1>
        <p className="err">This browser doesn&apos;t hold the key to that chat.</p>
        <p className="count">
          A chat only opens in the browser that started or joined it. <button type="button" className="link" onClick={() => go("")}>Back to your chats</button>
        </p>
      </main>
    );

  if (legacy)
    return (
      <main>
        <h1>Private chat</h1>
        <div className="warnbox">
          <b>This chat can&apos;t be opened any more.</b> It was made with an older kind of encryption
          that keeps every message readable if a key is ever stolen. Chats now use a stronger kind that
          erases each message&apos;s key after it is used, and the old ones can&apos;t be upgraded. End it
          to delete it, then start a new chat.
        </div>
        <div className="row" style={{ justifyContent: "flex-start" }}>
          <button type="button" className="danger" onClick={endChat}>End chat and delete keys</button>
          <button type="button" onClick={forgetHere}>Delete my key here</button>
        </div>
        {err ? <p className="err">{err}</p> : null}
      </main>
    );

  if (gone)
    return (
      <main>
        <h1>Private chat</h1>
        <div className="warnbox">
          {gone === "deleted"
            ? "This chat was ended. Its messages have been removed from this site and the key has been deleted from this browser, so it can't be read again."
            : "The server no longer has this chat."}
        </div>
        <div className="row" style={{ justifyContent: "flex-start" }}>
          <button
            type="button"
            onClick={() => {
              dropRoom(room.id);
              go("");
            }}
          >
            {gone === "deleted" ? "Back to your chats" : "Remove it from this browser"}
          </button>
        </div>
      </main>
    );

  const proven = new Set(items.filter((i) => i.msg?.kind === "proof").map((i) => (i.msg as { uid: string }).uid));
  const provable = mine.filter((e) => e.commitV === 2 && !proven.has(e.uid));

  return (
    <main>
      <p className="count" style={{ marginBottom: 4 }}>
        <button type="button" className="link" onClick={() => go("")}>← Your chats</button>
      </p>
      <h1>Private chat</h1>

      <div className="card chat-head">
        {role === "a" ? (
          <p>
            <span className="badge revealed">You made the link</span>{" "}
            {introduced ? (
              <>The other person only sees you as <span className="mono">{me ?? "…"}</span>, a made-up name used only in this chat.</>
            ) : (
              <>They can&apos;t see anything about you yet. First compare the safety code below with the other person, then say hello.</>
            )}
          </p>
        ) : source ? (
          <p>
            <span className="badge revealed">They said hello</span> You are talking to{" "}
            <span className="mono">{source.id}</span>. It&apos;s a made-up name used only in this chat,
            so it tells you nothing about who they are. Any posts they prove below were written
            with the key they show.
          </p>
        ) : badId ? (
          <p className="err">Their hello didn&apos;t check out. Be careful with this chat.</p>
        ) : (
          <p>
            <span className="badge unknown">Waiting for them</span> They&apos;ll say hello once they
            have compared the safety code.
          </p>
        )}
        {role === "a" && !introduced ? (
          <div className="row" style={{ justifyContent: "flex-start", marginTop: 0 }}>
            <button type="button" className="primary" onClick={introduce} disabled={introducing || !loaded || !keys}>
              {introducing ? "Saying hello…" : "The codes match: say hello"}
            </button>
          </div>
        ) : null}
        <p className="count">
          Safety code <span className="mono">{keys?.safety ?? "…"}</span>. Ask the other person to
          read out their code. If it&apos;s different, someone is listening in the middle. Stop
          chatting.
        </p>
        <div className="row chat-tools">
          <label className="count">
            <select value={ttl} onChange={(e) => changeTimer(Number(e.target.value))} aria-label="Message timer">
              {TIMERS.map(([v, label]) => (
                <option key={v} value={v}>{label}</option>
              ))}
            </select>
          </label>
          <span>
            <button type="button" className="link" onClick={saveTranscript}>Save transcript</button>
            <button type="button" className="link" onClick={forgetHere} title="Erases only this device's key. The other person can still read the chat.">Delete my key here</button>
            <button type="button" className="link danger" onClick={endChat} title="Removes every message from this site and erases the key on both sides.">End chat and delete keys</button>
          </span>
        </div>
      </div>

      <div className="chat-log" aria-live="polite">
        {loaded && items.length === 0 ? <p className="empty">No messages yet.</p> : null}
        {!loaded && !err ? <p className="empty">Loading…</p> : null}
        {items.map((it) => {
          const m = it.msg;
          const flag = flags[it.id];
          if (!m) return <p className="err chat-note" key={it.id}>{flag}</p>;
          const me = m.from === role;
          const whoLabel = me ? "You" : m.from === "a" ? "They" : "The other person";
          if (m.kind === "hello") return null;
          if (m.kind === "id")
            return m.from === "a" ? (
              <p className="count chat-note" key={it.id}>
                {me ? "You said hello with this chat's made-up name." : "They said hello."} <Stamp ms={m.t} />
              </p>
            ) : null;
          if (m.kind === "timer")
            return (
              <p className="count chat-note" key={it.id}>
                {whoLabel} set the timer to &quot;{timerLabel(m.ttl)}&quot;. <Stamp ms={m.t} />
              </p>
            );
          if (m.kind === "proof") {
            const p = proofs[it.id];
            if (m.from !== "a") return null;
            return (
              <div className={`chat-proof ${p?.status ?? "checking"}`} key={it.id}>
                {p?.status === "ok" ? (
                  <>
                    <b>Checked.</b> {me ? "You showed that you" : "They showed that they"} wrote this post on the
                    public record{p.createdAt ? <> at <Stamp ms={p.createdAt} /></> : null}:{" "}
                    {onChat ? <span>{p.title || "a post"}</span> : <Link href={`/e/${m.uid}`} target="_blank">{p.title || "open entry"}</Link>}
                  </>
                ) : p?.status === "bad" ? (
                  <>
                    <b>Didn&apos;t check out.</b> {me ? "Your proof" : "They said they wrote"}{" "}
                    {onChat ? "this post" : <Link href={`/e/${m.uid}`} target="_blank">this entry</Link>}
                    {me ? " doesn't match the key in this browser." : ", but the proof doesn't match."}
                  </>
                ) : p?.status === "gone" ? (
                  <>A proof was sent for a post that couldn&apos;t be loaded.</>
                ) : (
                  <>Checking the proof against the public record…</>
                )}
                {flag ? <span className="err"> {flag}</span> : null}
              </div>
            );
          }
          return (
            <div className={`chat-msg ${me ? "me" : "them"}`} key={it.id}>
              <div className="chat-bubble">{m.text}</div>
              <div className="count">
                {whoLabel} · <Stamp ms={m.t} />
              </div>
              {flag ? <div className="err">{flag}</div> : null}
            </div>
          );
        })}
        <div ref={bottom} />
      </div>

      {err ? <p className="err">{err}</p> : null}
      <textarea
        className="plain"
        rows={3}
        maxLength={MAX_TEXT}
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) submit();
        }}
        placeholder={canSend ? "Write a message" : "You can reply once the other person has connected"}
        aria-label="Message"
        disabled={!canSend}
      />
      {!canSend ? (
        <p className="count">
          The chat is ready as soon as the other person&apos;s device connects. Nothing is lost: this
          happens by itself when they open the chat.
        </p>
      ) : null}
      <div className="row">
        <span className="count">Encrypted in this browser before it is sent.</span>
        <button type="button" className="primary" onClick={submit} disabled={sending || !text.trim() || !keys || !canSend}>
          {sending ? "Sending…" : "Send"}
        </button>
      </div>

      {role === "a" && !onChat ? (
        <div className="card">
          <p className="lede" style={{ marginBottom: 8 }}>
            <b>Show them a post is yours.</b> Pick one of your posts. Their browser will check it
            against the public record and confirm that the same person wrote that post and is
            chatting here. They won&apos;t learn your name or which other posts are yours.
          </p>
          {provable.length ? (
            <div className="row" style={{ justifyContent: "flex-start" }}>
              <select value={pick} onChange={(e) => setPick(e.target.value)} aria-label="Entry to prove">
                <option value="">Choose an entry…</option>
                {provable.map((e) => (
                  <option key={e.uid} value={e.uid}>
                    {(e.title || e.text).slice(0, 70)}
                  </option>
                ))}
              </select>
              <button type="button" onClick={prove} disabled={!pick}>
                Prove it
              </button>
            </div>
          ) : (
            <p className="count">
              {mine.length
                ? "You have already shown them every post this browser knows is yours."
                : "You haven't posted anything from this browser yet. When you do, come back here to show it."}
            </p>
          )}
          <p className="count">
            You can&apos;t take a proof back. The other person could pass it on, and then anyone they
            give it to could also check that the post is yours.
          </p>
        </div>
      ) : null}
    </main>
  );
}

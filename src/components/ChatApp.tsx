"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import Stamp from "./Stamp";
import {
  acceptJoin,
  decryptMessage,
  encryptMessage,
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
  type Message,
  type RoomKeys,
} from "@/lib/chat-crypto";
import {
  addInvite,
  addRoom,
  dropInvite,
  dropRoom,
  eraseInviteKey,
  exportAccess,
  findRoom,
  importAccess,
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
import type { CommitContent } from "@/lib/commit";
import { postWithTicket, warmTicket } from "@/lib/ticket-client";

type Route = { view: "home" } | { view: "join"; secret: string } | { view: "room"; id: string };

function readRoute(): Route {
  const h = location.hash;
  const secret = parseInviteFragment(h);
  if (secret) return { view: "join", secret };
  const m = /^#r=([0-9a-f-]{36})$/.exec(h);
  if (m) return { view: "room", id: m[1] };
  return { view: "home" };
}

function go(hash: string) {
  // replaceState keeps link secrets out of the back button's history.
  history.replaceState(null, "", hash ? `/chat#${hash}` : "/chat");
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

export default function ChatApp() {
  const [route, setRoute] = useState<Route | null>(null);
  useEffect(() => {
    const on = () => setRoute(readRoute());
    on();
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);

  if (!route) return <p className="empty">Loading…</p>;
  if (typeof crypto === "undefined" || !crypto.subtle)
    return <p className="err">This browser can&apos;t do the encryption private chats need.</p>;
  if (route.view === "join") return <Join secret={route.secret} />;
  if (route.view === "room") return <Room key={route.id} id={route.id} />;
  return <Home />;
}

// ------------------------------------------------------------------------------------------
// Home: start a chat, see links and chats
// ------------------------------------------------------------------------------------------

function Home() {
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
  const [restoreText, setRestoreText] = useState("");
  const [trap, setTrap] = useState("");

  const reload = useCallback(() => {
    const s = loadChats();
    setInvites(s.invites);
    setRooms(s.rooms);
  }, []);

  useEffect(() => {
    reload();
    warmTicket();
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
            const master = await acceptJoin(inv.secret, inv.privs?.[room.slot] ?? null, room.id, room.join, room.slot);
            if (master) {
              addRoom({ id: room.id, role: "a", master, createdAt: room.createdAt, via: inv.id });
              // The key for this chat is no longer needed, and nothing may be able to re-derive it.
              eraseInviteKey(inv.id, room.slot);
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

  function restore() {
    setErr(null);
    setNote(null);
    try {
      const r = importAccess(restoreText);
      addRoom(r);
      setRestoreText("");
      reload();
      go(`r=${r.id}`);
    } catch (e) {
      setErr(errText(e, "Could not read that chat key"));
    }
  }

  const linkOf = (inv: StoredInvite) => `${location.origin}/chat#${inviteFragment(inv.secret)}`;

  return (
    <main>
      <h1>Private chat</h1>
      <p className="lede">
        An encrypted conversation between two people. Messages are locked in your browser before
        they leave it; this site stores them but cannot read them. You start one by making a
        link and giving it to the other person.
      </p>

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
        <div className="row" style={{ justifyContent: "flex-start" }}>
          <button type="button" className="primary" onClick={create} disabled={busy}>
            {busy ? "Making the link…" : "Make a chat link"}
          </button>
        </div>
        {err ? <p className="err">{err}</p> : null}
        {note ? <p className="notice">{note}</p> : null}
      </div>

      <p className="count">
        The other person never sees a name, an address or an account. If you are the source, they
        see a pseudonym made for that one chat, and only you can show them which public entries
        are yours, one at a time, inside the chat. <Link href="/mine">Back up your key</Link> so
        you can still do that on another device.
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
              How you send this link matters more than anything else here. Whoever opens it first
              becomes the other person in the chat, and a link sent from an account in your name
              tells the receiver who you are. Keep this page open, or come back to it in this
              same browser: the chat appears here once the link is opened.
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
                {r.role === "a" ? "You are the source" : "You opened a link"}
              </span>{" "}
              <span className="count">Started <Stamp ms={r.createdAt} /></span>
            </span>
            <button type="button" className="primary" onClick={() => go(`r=${r.id}`)}>
              Open
            </button>
          </div>
        </div>
      ))}

      <details>
        <summary>Move a chat from another browser</summary>
        <p className="count">
          Paste a chat key (made with &quot;Copy chat key&quot; inside a chat) to open that chat here too.
        </p>
        <textarea
          className="plain"
          rows={3}
          value={restoreText}
          onChange={(e) => setRestoreText(e.target.value)}
          aria-label="Chat key"
          spellCheck={false}
        />
        <div className="row" style={{ justifyContent: "flex-start" }}>
          <button type="button" onClick={restore} disabled={!restoreText.trim()}>
            Add chat
          </button>
        </div>
      </details>

      <details>
        <summary>What this does and doesn&apos;t protect</summary>
        <ul className="chat-notes">
          <li>The site can&apos;t read your messages, and can&apos;t tell which public posts a chat is about unless someone checks a proof.</li>
          <li>The site&apos;s server does see the internet address a browser connects from, though it keeps no log of it. To hide that as well, use Tor Browser.</li>
          <li>Anyone holding your unlocked phone or computer can read the chats in its browser. Use the delete timer or &quot;Delete chat&quot; if that worries you.</li>
          <li>Deleting removes messages from this site. It can&apos;t remove a copy the other person saved or photographed, and encrypted copies stay in the site&apos;s backups for up to 14 days.</li>
          <li>Compare the safety code with the other person if you can. Matching codes mean nobody is in between.</li>
        </ul>
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
        if (!addRoom({ id: j.roomId, role: "b", master: j.master, createdAt: Date.now(), via: id }))
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
            Someone has invited you to an encrypted conversation. Messages are locked in your
            browser before they leave it; this site stores them but cannot read them.
          </p>
          <ul className="chat-notes">
            <li>Open it in the browser you will keep using. The chat&apos;s key is stored in this browser, and the link may only work once.</li>
            <li>You don&apos;t need an account, and the other person learns nothing about you except what you type.</li>
            <li>The other person can prove they wrote particular entries on Zesuro&apos;s public record without telling you who they are.</li>
          </ul>
          <div className="row" style={{ justifyContent: "flex-start" }}>
            <button type="button" className="primary" onClick={join} disabled={state === "busy"}>
              {state === "busy" ? "Opening…" : "Open the chat"}
            </button>
          </div>
        </div>
      ) : null}
      {state === "used" ? (
        <div className="warnbox">
          <b>This link has already been used, or was cancelled.</b> If you did not open it yourself
          (in another browser, say), someone else may have. Tell the person who sent it, through a
          different channel, and ask for a new link. If you did open it before, go back to the
          browser you used: the chat is under <Link href="/chat">Private chat</Link> there.
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

interface Item {
  id: number;
  at: number;
  msg: Message | null;
}
type ProofState = { status: "checking" | "ok" | "bad" | "gone"; title?: string; createdAt?: number };

function Room({ id }: { id: string }) {
  const [room] = useState<StoredRoom | null>(() => findRoom(id));
  const [keys, setKeys] = useState<RoomKeys | null>(null);
  const [items, setItems] = useState<Item[]>([]);
  const [loaded, setLoaded] = useState(false);
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
  const [copied, setCopied] = useState(false);

  const cursor = useRef(0);
  const polling = useRef(false);
  const checkedProofs = useRef(new Set<number>());
  const itemsRef = useRef<Item[]>([]);
  const hadTimer = useRef(room?.hadTimer ?? false);
  const bottom = useRef<HTMLDivElement>(null);
  const role = room?.role ?? "b";

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

  const poll = useCallback(async () => {
    if (!keys || !room || polling.current) return;
    polling.current = true;
    try {
      for (;;) {
        const r = await fetch(`/api/chat/rooms/${room.id}?after=${cursor.current}`, {
          cache: "no-store",
          headers: { "x-chat-auth": keys.token },
        });
        if (r.status === 410) return setGone("deleted");
        if (r.status === 404) return setGone("missing");
        if (!r.ok) throw new Error("Could not reach the server");
        const d = (await r.json()) as { ttl: number; more: boolean; messages: { id: number; blob: string; at: number }[] };
        setTtl(d.ttl);
        if (d.messages.length) {
          const add: Item[] = [];
          for (const m of d.messages) {
            const msg = await decryptMessage(keys, room.id, m.blob);
            add.push({ id: m.id, at: m.at, msg });
            // Only a timer message from one of the two of you counts: the server's own say-so
            // must not be able to switch off the "messages are missing" warnings.
            if (msg?.kind === "timer" && msg.ttl > 0 && !hadTimer.current) {
              hadTimer.current = true;
              patchRoom(room.id, { hadTimer: true });
            }
          }
          cursor.current = d.messages[d.messages.length - 1].id;
          itemsRef.current = [...itemsRef.current, ...add];
          setItems(itemsRef.current);
        }
        setErr(null);
        if (!d.more) break;
      }
      setLoaded(true);
    } catch (e) {
      setErr(errText(e, "Could not reach the server"));
    } finally {
      polling.current = false;
    }
  }, [keys, room]);

  useEffect(() => {
    if (!keys) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const loop = async () => {
      await poll();
      if (!stop) timer = setTimeout(loop, POLL_MS);
    };
    loop();
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  }, [keys, poll]);

  const send = useCallback(
    async (body: Body) => {
      if (!keys || !room) return;
      const own = itemsRef.current.filter((i) => i.msg?.from === room.role).map((i) => i.msg!.n);
      const n = Math.max(findRoom(room.id)?.sent ?? 0, own.length ? Math.max(...own) + 1 : 0);
      const blob = await encryptMessage(keys, room.id, room.role, n, body);
      // Claim the number first, so a retry after a lost reply can't reuse it.
      patchRoom(room.id, { sent: n + 1 });
      const res = await fetch(`/api/chat/rooms/${room.id}`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-chat-auth": keys.token },
        body: JSON.stringify({ blob }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || "Could not send");
      }
      await poll();
    },
    [keys, room, poll],
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
        out[it.id] = "This message could not be read. It was not written by either of you, or it was altered.";
        continue;
      }
      const sentHere = room ? findRoom(room.id)?.sent : undefined;
      if (room && typeof sentHere === "number" && m.from === room.role && m.n >= sentHere)
        out[it.id] =
          "This message was not sent from this browser. If you use this chat on another device, that is expected; if not, someone else holds this chat's key.";
      const want = next[m.from];
      if (want === undefined) {
        if (m.n > 0 && !hadTimer.current) out[it.id] = "Earlier messages from this person are missing.";
      } else if (m.n > want) out[it.id] = "One or more messages before this one are missing.";
      else if (m.n < want) out[it.id] = "This message is a repeat or out of order.";
      next[m.from] = Math.max(want ?? 0, m.n + 1);
    }
    return out;
  }, [items, room]);

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

  async function removeChat() {
    if (!keys || !room) return;
    if (!window.confirm("Delete this chat for both of you? Every message is removed from this site. This can't be undone.")) return;
    try {
      const r = await fetch(`/api/chat/rooms/${room.id}`, { method: "DELETE", headers: { "x-chat-auth": keys.token } });
      if (!r.ok && r.status !== 410) throw new Error("Could not delete the chat");
      dropRoom(room.id);
      go("");
    } catch (e) {
      setErr(errText(e, "Could not delete the chat"));
    }
  }

  function saveTranscript() {
    if (!room) return;
    const who = (f: "a" | "b") => (f === "a" ? "SOURCE" : "CONTACT");
    const lines = [
      "Zesuro private chat transcript",
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
      else lines.push(`${head}: introduced themselves (chat key ${m.pub}, signature ${m.sig})`);
      if (flags[it.id]) lines.push(`    WARNING: ${flags[it.id]}`);
    }
    const url = URL.createObjectURL(new Blob([lines.filter((l) => l !== "").join("\n") + "\n"], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `zesuro-chat-${room.id.slice(0, 8)}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5_000);
  }

  if (!room)
    return (
      <main>
        <h1>Private chat</h1>
        <p className="err">This browser doesn&apos;t hold the key to that chat.</p>
        <p className="count">
          Chats can only be opened in the browser that started or joined them, unless you move the
          chat key across. <button type="button" className="link" onClick={() => go("")}>Back to your chats</button>
        </p>
      </main>
    );

  if (gone)
    return (
      <main>
        <h1>Private chat</h1>
        <div className="warnbox">
          {gone === "deleted"
            ? "This chat was deleted. Its messages have been removed from this site."
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
            Remove it from this browser
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
            <span className="badge revealed">You are the source</span>{" "}
            {introduced ? (
              <>The other person sees you only as <span className="mono">{me ?? "…"}</span>, a name that exists for this chat alone.</>
            ) : (
              <>You haven&apos;t introduced yourself yet. Compare the safety code below with the other person first, then introduce yourself.</>
            )}
          </p>
        ) : source ? (
          <p>
            <span className="badge revealed">Source introduced</span> You are talking to{" "}
            <span className="mono">{source.id}</span>. That name exists only in this chat and says
            nothing about who they are. Entries they prove below were sealed by the key they show.
          </p>
        ) : badId ? (
          <p className="err">The other person&apos;s introduction did not check out. Treat this chat with suspicion.</p>
        ) : (
          <p>
            <span className="badge unknown">Source not yet introduced</span> They choose when to
            introduce themselves, after comparing the safety code.
          </p>
        )}
        {role === "a" && !introduced ? (
          <div className="row" style={{ justifyContent: "flex-start", marginTop: 0 }}>
            <button type="button" className="primary" onClick={introduce} disabled={introducing || !loaded || !keys}>
              {introducing ? "Introducing…" : "The code matches: introduce myself"}
            </button>
          </div>
        ) : null}
        <p className="count">
          Safety code <span className="mono">{keys?.safety ?? "…"}</span>. If the other person sees a
          different code, someone is in between: stop.
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
            <button
              type="button"
              className="link"
              onClick={async () => {
                if (await copyText(exportAccess(room), "Copy this chat key")) {
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }
              }}
              title="A key that opens this chat in another browser. Treat it like a password."
            >
              {copied ? "Chat key copied" : "Copy chat key"}
            </button>
            <button type="button" className="link" onClick={removeChat}>Delete chat</button>
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
          const whoLabel = me ? "You" : m.from === "a" ? "The source" : "The other person";
          if (m.kind === "id")
            return m.from === "a" ? (
              <p className="count chat-note" key={it.id}>
                {me ? "You introduced yourself with this chat's pseudonym." : "The source introduced themselves."} <Stamp ms={m.t} />
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
                    <b>Verified.</b> {me ? "You proved that you" : "The source"} sealed this entry on the
                    public record{p.createdAt ? <> at <Stamp ms={p.createdAt} /></> : null}:{" "}
                    <Link href={`/e/${m.uid}`} target="_blank">{p.title || "open entry"}</Link>
                  </>
                ) : p?.status === "bad" ? (
                  <>
                    <b>Not verified.</b> {me ? "Your proof" : "The source claimed"}{" "}
                    <Link href={`/e/${m.uid}`} target="_blank">this entry</Link>
                    {me ? " does not match this browser's key." : ", but the proof does not match it."}
                  </>
                ) : p?.status === "gone" ? (
                  <>A proof was sent for an entry that could not be loaded.</>
                ) : (
                  <>Checking a proof against the public record…</>
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
        placeholder="Write a message"
        aria-label="Message"
      />
      <div className="row">
        <span className="count">Encrypted in this browser before it is sent.</span>
        <button type="button" className="primary" onClick={submit} disabled={sending || !text.trim() || !keys}>
          {sending ? "Sending…" : "Send"}
        </button>
      </div>

      {role === "a" ? (
        <div className="card">
          <p className="lede" style={{ marginBottom: 8 }}>
            <b>Prove a post is yours.</b> Pick one of your entries and the other person&apos;s browser
            checks it against the public record. They learn that this entry and this chat come from the
            same key, and they receive that entry&apos;s key and salt. They do not learn your name, and
            no other entry of yours is linked by it.
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
                ? "You have proved every entry this browser knows as yours."
                : "You haven't sealed anything from this browser yet. When you do, come back here to prove it."}
            </p>
          )}
          <p className="count">
            A proof can&apos;t be taken back. The other person could pass the entry&apos;s key and salt to someone else, who could then check the same thing.
          </p>
        </div>
      ) : null}
    </main>
  );
}

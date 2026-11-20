// End-to-end smoke test. Acts like a browser with its own, independent crypto.
// Usage: npm run smoke   (server must be running; BASE_URL defaults to http://localhost:3000)
import { webcrypto, createHash, randomUUID } from "node:crypto";
import * as CM from "../src/lib/commit.ts";

const { subtle } = webcrypto;
const BASE = process.env.BASE_URL || "http://localhost:3000";
const enc = new TextEncoder();
// Forms must present a ticket from the server (see lib/spam.ts). One is enough for the run.
const TICKET = (await (await fetch(BASE + "/api/ticket")).json()).ticket; // for the few requests that use it by hand
const hex = (b) => Buffer.from(b).toString("hex");
const b64u = (b) => Buffer.from(b).toString("base64url");
const sha256 = (s) => createHash("sha256").update(s).digest("hex");

let failed = 0;
function check(name, cond, extra = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond ? "" : "  " + extra}`);
  if (!cond) failed++;
}

async function newKey() {
  const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const priv = await subtle.exportKey("jwk", pair.privateKey);
  return { priv, pub: { crv: priv.crv, kty: priv.kty, x: priv.x, y: priv.y } };
}
const canon = (p) => JSON.stringify({ crv: p.crv, kty: p.kty, x: p.x, y: p.y });

// Entries are version 2: a key per entry, and a commitment that covers the entry's content.
const PKCS8_ED = Buffer.from("302e020100300506032b657004220420", "hex");
async function prf(k, label) {
  const hk = await subtle.importKey("raw", Buffer.from(k.priv.d, "base64url"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", hk, enc.encode(label)));
}
async function entryKeyN(k, nonce) {
  const sign = await subtle.importKey("pkcs8", Buffer.concat([PKCS8_ED, Buffer.from(await prf(k, `whenisaid:entry-key:v2:${nonce}`))]), { name: "Ed25519" }, true, ["sign"]);
  return { x: (await subtle.exportKey("jwk", sign)).x, sign };
}
const salt = async (k, nonce) => hex(await prf(k, `whenisaid:entry-salt:v2:${nonce}`));
const EMPTY = { uid: "", title: "", text: "", placeMode: "none", place: null, secretCommit: null, mode: "manual" };
async function commit(k, nonce, content = EMPTY) {
  return sha256(CM.commitInput((await entryKeyN(k, nonce)).x, await salt(k, nonce), sha256(CM.contentString(content))));
}
async function opening(k, uid, nonce, handle) {
  const { x, sign } = await entryKeyN(k, nonce);
  const sig = await subtle.sign({ name: "Ed25519" }, sign, enc.encode(CM.revealMessageV2(uid, handle)));
  return { v: 2, pub: { kty: "OKP", crv: "Ed25519", x }, salt: await salt(k, nonce), handle, sig: b64u(sig) };
}

// Tickets work once, so every ticketed request gets a fresh one.
const newTicket = async () => (await (await fetch(BASE + "/api/ticket")).json()).ticket;
async function api(method, path, body) {
  const ticketed = method === "POST" && (path === "/api/entries" || path.endsWith("/comments") || path.endsWith("/report"));
  const tk = ticketed ? await newTicket() : null;
  const r = await fetch(BASE + path, {
    method,
    headers: { "content-type": "application/json" },
    body: body
      ? JSON.stringify(
          ticketed
            ? { ticket: tk, ...(path === "/api/entries" && body.commitV === undefined ? { commitV: 2 } : {}), ...body }
            : body,
        )
      : undefined,
  });
  let j = null;
  try { j = await r.json(); } catch {}
  return { status: r.status, body: j };
}

async function seal(k, extra = {}) {
  const uid = randomUUID();
  const nonce = hex(webcrypto.getRandomValues(new Uint8Array(16)));
  const MARK = "";
  const secret = extra.secret ?? null; // { parts, place, salt }
  const body = {
    uid, nonce,
    title: extra.title ?? "Smoke test",
    placeMode: extra.placeMode ?? "none",
    place: extra.place ?? null,
    secretCommit: secret ? sha256(JSON.stringify([secret.parts, secret.place, secret.salt])) : null,
    secretBlob: secret ? "c21va2U" : undefined,
    // Date and locked entries hand the server the payload; manual ones keep it until release.
    secret: (extra.mode ?? "manual") === "manual" ? null : secret,
    text: extra.text ?? `smoke test ${uid}`,
    commitment: await commit(k, nonce, {
      uid,
      title: CM.normTitle(extra.title ?? "Smoke test"),
      text: CM.normText(extra.text ?? `smoke test ${uid}`),
      placeMode: extra.placeMode ?? "none",
      place: extra.place ? { lat: Math.round(extra.place.lat * 1e5) / 1e5, lng: Math.round(extra.place.lng * 1e5) / 1e5, label: (extra.place.label ?? "").trim().replace(/\s+/g, " ") } : null,
      secretCommit: secret ? sha256(JSON.stringify([secret.parts, secret.place, secret.salt])) : null,
      mode: extra.mode ?? "manual",
    }),
    mode: extra.mode ?? "manual",
    revealAt: extra.revealAt ?? null,
    deadlineAt: extra.deadlineAt ?? null,
    opening: extra.handle ? await opening(k, uid, nonce, extra.handle) : null,
    revealPublic: extra.revealPublic,
  };
  const res = await api("POST", "/api/entries", body);
  return { uid, nonce, res };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const MARK_ = "";

async function rawPostEarly(path, body) {
  const r = await fetch(BASE + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  let j = null; try { j = await r.json(); } catch {}
  return { status: r.status, body: j };
}
const k = await newKey();
const other = await newKey();

// 1. Manual seal
const a = await seal(k);
check("manual seal accepted (201)", a.res.status === 201, JSON.stringify(a.res.body));
const e1 = a.res.body?.entry;
check("anonymous, no name, no opening", e1?.status === "anonymous" && e1.handle === null && e1.opening === null);
check("sealed time is close to now", Math.abs(e1.createdAt - Date.now()) < 10_000);

// 1b. Commitments cover content and can't be copied
check("entries are version 2", e1?.commitV === 2);
{
  const noV = await rawPostEarly("/api/entries", { uid: randomUUID(), nonce: hex(webcrypto.getRandomValues(new Uint8Array(16))), title: "t", text: "x", commitment: "a".repeat(64), mode: "manual", placeMode: "none", ticket: await newTicket() });
  check("an entry without a commitment version is refused", noV.status === 409, JSON.stringify(noV.body));
  const copy1 = await api("POST", "/api/entries", { uid: randomUUID(), nonce: hex(webcrypto.getRandomValues(new Uint8Array(16))), title: "Copycat", text: "Words the victim never wrote", commitment: e1.commitment, mode: "manual", placeMode: "none" });
  check("another entry can't reuse an existing commitment", copy1.status === 409, JSON.stringify(copy1.body));
  const copy2 = await api("POST", "/api/entries", { uid: randomUUID(), nonce: e1.nonce, title: "Copycat", text: "Words the victim never wrote", commitment: "b".repeat(64), mode: "manual", placeMode: "none" });
  check("another entry can't reuse an existing nonce", copy2.status === 409, JSON.stringify(copy2.body));
  // A commitment is bound to its own entry id and text: moving the opening elsewhere fails.
  const other1 = await seal(k, { title: "Bound one", text: `bound text one ${randomUUID()}` });
  const stray = await api("POST", `/api/entries/${other1.uid}/reveal`, await opening(k, a.uid, a.nonce, "Alex"));
  check("an opening made for one entry doesn't open another", stray.status === 403, JSON.stringify(stray.body));
}

// 2. Unlinkability: same key, different commitments
const b = await seal(k);
check("two entries from one key have different commitments", a.res.body.entry.commitment !== b.res.body.entry.commitment);

// 3. Reveal with a different key must fail
let bad = await api("POST", `/api/entries/${a.uid}/reveal`, await opening(other, a.uid, a.nonce, "Mallory"));
check("reveal with the wrong key is rejected (403)", bad.status === 403, JSON.stringify(bad.body));

// 4. Reveal with the right key
let good = await api("POST", `/api/entries/${a.uid}/reveal`, await opening(k, a.uid, a.nonce, "Alex R."));
check("reveal with the right key works", good.status === 200 && good.body?.entry?.status === "revealed" && good.body.entry.handle === "Alex R.", JSON.stringify(good.body));
let again = await api("POST", `/api/entries/${a.uid}/reveal`, await opening(k, a.uid, a.nonce, "Someone else"));
check("cannot reveal twice (409)", again.status === 409);

// 5. A signature for one handle cannot be reused for another
const c = await seal(k);
const op = await opening(k, c.uid, c.nonce, "Real Name");
const swapped = await api("POST", `/api/entries/${c.uid}/reveal`, { ...op, handle: "Fake Name" });
check("signature cannot be reused with a different name", swapped.status === 403);

// 6. Validation
check("empty text rejected", (await seal(k, { text: "   " })).res.status === 400);
check("over-long text rejected", (await seal(k, { text: "x".repeat(5001) })).res.status === 400);
check("past reveal date rejected", (await seal(k, { mode: "date", revealAt: Date.now() - 1000, handle: "X" })).res.status === 400);
check("date mode without a name rejected", (await seal(k, { mode: "date", revealAt: Date.now() + 120_000 })).res.status === 400);

// 7. Deadline -> Unknown
const d = await seal(k, { deadlineAt: Date.now() + 32_000 });
check("deadline accepted", d.res.status === 201);

// 8. Locked reveal fires by itself, and cannot be cancelled early
const t = Date.now() + 34_000;
const l = await seal(k, { mode: "locked", revealAt: t, handle: "Locked Lou" });
check("locked seal accepted", l.res.status === 201, JSON.stringify(l.res.body));
check("locked entry shows no name before its time", l.res.body?.entry?.handle === null && l.res.body.entry.opening === null);
const early = await api("POST", `/api/entries/${l.uid}/reveal`, await opening(k, l.uid, l.nonce, "Lou early"));
check("locked entry cannot be revealed early (403)", early.status === 403);

// 8b. Reveal date privacy (default: hidden)
const hiddenAt = Date.now() + 3_600_000;
const hid = await seal(k, { mode: "date", revealAt: hiddenAt, handle: "Hidden Hana" });
const he = hid.res.body?.entry;
check("private reveal date: seal accepted", hid.res.status === 201, JSON.stringify(hid.res.body));
check("private reveal date: not in the entry response", he?.revealAt === null && he?.revealDatePublic === false && he?.schedule === null);
const hl = (await api("GET", "/api/entries?limit=100")).body?.entries?.find((e) => e.uid === hid.uid);
check("private reveal date: not in the public list", hl?.revealAt === null && hl?.schedule === null);
check("private reveal date: raw date appears nowhere in the JSON", !JSON.stringify(hl).includes(String(hiddenAt)));
check("private reveal date: hash v2 with a schedule commitment", he?.hashVersion === 3 && /^[0-9a-f]{64}$/.test(he?.schedCommit ?? ""));

const shownAt = Date.now() + 3_600_000 + 1234;
const pub = await seal(k, { mode: "date", revealAt: shownAt, handle: "Public Pete", revealPublic: true });
const pe = pub.res.body?.entry;
check("public reveal date: shown", pe?.revealAt === shownAt && pe?.revealDatePublic === true);
check("public reveal date: schedule opens and matches its commitment",
  pe?.schedule && sha256(JSON.stringify([pe.schedule.revealAt, pe.schedule.deadlineAt, pe.schedule.salt])) === pe.schedCommit);

const withDeadline = await seal(k, { mode: "date", revealAt: Date.now() + 3_600_000, deadlineAt: Date.now() + 7_200_000, handle: "Dee", revealPublic: true });
check("public date + pending deadline: deadline and schedule stay hidden",
  withDeadline.res.body?.entry?.deadlineAt === null && withDeadline.res.body.entry.schedule === null);

// 8c. Search
const needle = `needle-${randomUUID()}`;
await seal(k, { text: `find me ${needle}` });
const found = (await api("GET", `/api/entries?q=${encodeURIComponent(needle)}`)).body?.entries ?? [];
check("search finds the entry", found.length === 1 && found[0].text.includes(needle));
const pctA = await seal(k, { text: `${needle} 100% sure` });
const pctB = await seal(k, { text: `${needle} 100x sure` });
const pct = (await api("GET", `/api/entries?q=${encodeURIComponent(needle + " 100%")}`)).body?.entries ?? [];
check("search treats % literally", pct.length === 1 && pct[0].uid === pctA.uid && pctB.res.status === 201);

// 8d. Sealed-date range
const dayOf = (ms) => new Date(ms).toISOString().slice(0, 10);
const todayUtc = dayOf(Date.now());
const tomorrowUtc = dayOf(Date.now() + 86_400_000);
const inRange = (await api("GET", `/api/entries?q=${encodeURIComponent(needle)}&from=${todayUtc}&to=${todayUtc}`)).body?.entries ?? [];
check("date range: today includes today's entries", inRange.length >= 1);
const future = (await api("GET", `/api/entries?q=${encodeURIComponent(needle)}&from=${tomorrowUtc}`)).body?.entries ?? [];
check("date range: starting tomorrow finds nothing", future.length === 0);
const past = (await api("GET", `/api/entries?q=${encodeURIComponent(needle)}&to=2000-01-01`)).body?.entries ?? [];
check("date range: ending in 2000 finds nothing", past.length === 0);
const junk = (await api("GET", `/api/entries?q=${encodeURIComponent(needle)}&from=not-a-date`)).body?.entries ?? [];
check("date range: invalid date is ignored", junk.length >= 1);

// 8e. Links in the text become anchors on the public page
const linked = await seal(k, { text: `see https://example.com/a?b=1, and <script>x</script> ${needle}` });
const html = await (await fetch(`${BASE}/record?q=${encodeURIComponent(needle)}`)).text();
check("link in a new entry is plain text, not an anchor", linked.res.status === 201 && !html.includes('href="https://example.com/a?b=1"') && html.includes("https://example.com/a?b=1"));
for (const t of ["1", "2", "3"]) await api("POST", `/api/entries/${linked.uid}/vote`, { voter: t.repeat(64), value: 1 });
const htmlLiked = await (await fetch(`${BASE}/record?q=${encodeURIComponent(needle)}`, { redirect: "follow" })).text();
check("link becomes an anchor once the entry has 3 net likes", htmlLiked.includes('href="https://example.com/a?b=1"'));
check("html in text stays escaped", !html.includes("<script>x</script>"));

// 8f. Title
check("title is required", (await api("POST", "/api/entries", { ...(await (async () => { const n = hex(webcrypto.getRandomValues(new Uint8Array(16))); return { uid: randomUUID(), nonce: n, text: "x", commitment: await commit(k, n), mode: "manual" }; })()) })).status === 400);
check("title too long is rejected", (await seal(k, { title: "t".repeat(101) })).res.status === 400);
const titled = await seal(k, { title: `Headline ${needle}`, text: "body without the word" });
const byTitle = (await api("GET", `/api/entries?q=${encodeURIComponent(needle)}`)).body?.entries ?? [];
check("search matches the title", byTitle.some((e) => e.uid === titled.uid && e.title === `Headline ${needle}`));

// 8g. Redacted text, manual release
const salt1 = hex(webcrypto.getRandomValues(new Uint8Array(16)));
const sec1 = { parts: ["Mr Brown"], place: null, salt: salt1 };
const red = await seal(k, { text: `${MARK_} will resign ${needle}`, secret: sec1 });
const re = red.res.body?.entry;
check("redacted seal accepted", red.res.status === 201, JSON.stringify(red.res.body));
check("redacted text stays hidden", re?.parts === null && re?.secret === null && re?.redactions === 1);
check("redacted passage appears nowhere in the public JSON", !JSON.stringify((await api("GET", `/api/entries?q=${encodeURIComponent(needle)}`)).body).includes("Mr Brown"));
const noSecret = await api("POST", `/api/entries/${red.uid}/reveal`, await opening(k, red.uid, red.nonce, "Alex"));
check("release without the hidden parts is rejected", noSecret.status === 400, JSON.stringify(noSecret.body));
const wrongSecret = await api("POST", `/api/entries/${red.uid}/reveal`, { ...(await opening(k, red.uid, red.nonce, "Alex")), secret: { ...sec1, parts: ["Mr Green"] } });
check("release with different hidden parts is rejected", wrongSecret.status === 400, JSON.stringify(wrongSecret.body));
const okSecret = await api("POST", `/api/entries/${red.uid}/reveal`, { ...(await opening(k, red.uid, red.nonce, "Alex")), secret: sec1 });
const oe = okSecret.body?.entry;
check("release opens the redacted passage", okSecret.status === 200 && oe?.parts?.[0] === "Mr Brown", JSON.stringify(okSecret.body));
check("opened hidden parts verify against the commitment", oe?.secret && sha256(JSON.stringify([oe.secret.parts, oe.secret.place, oe.secret.salt])) === oe.secretCommit);

// 8h. Places
const pub2 = await seal(k, { placeMode: "public", place: { lat: -33.8688, lng: 151.2093, label: "Sydney" } });
check("public place is shown", pub2.res.body?.entry?.place?.label === "Sydney" && pub2.res.body.entry.placeHidden === false, JSON.stringify(pub2.res.body));
check("invalid place rejected", (await seal(k, { placeMode: "public", place: { lat: 999, lng: 0, label: "" } })).res.status === 400);
const hidPlace = { parts: [], place: { lat: 48.8584, lng: 2.2945, label: "Tower" }, salt: hex(webcrypto.getRandomValues(new Uint8Array(16))) };
const hpAt = Date.now() + 31_000;
const hp = await seal(k, { placeMode: "hidden", secret: hidPlace, mode: "date", revealAt: hpAt, handle: "Pierre", text: `meet me ${needle}` });
check("hidden place: seal accepted", hp.res.status === 201, JSON.stringify(hp.res.body));
check("hidden place is not in the public JSON", hp.res.body?.entry?.place === null && hp.res.body.entry.placeHidden === true && !JSON.stringify(hp.res.body).includes("48.8584"));
const badCommit = await seal(k, { placeMode: "hidden", secret: hidPlace, mode: "date", revealAt: Date.now() + 120_000, handle: "Pierre" });
check("scheduled hidden place accepted when commitment matches", badCommit.res.status === 201);
const mismatch = await api("POST", "/api/entries", { ...(await (async () => { const n = hex(webcrypto.getRandomValues(new Uint8Array(16))); const u = randomUUID(); return { uid: u, nonce: n, title: "t", text: "x", commitment: await commit(k, n), mode: "date", revealAt: Date.now() + 120_000, opening: await opening(k, u, n, "P"), placeMode: "hidden", secretCommit: "0".repeat(64), secretBlob: "abc", secret: hidPlace }; })()) });
check("scheduled secret that does not match its commitment is rejected", mismatch.status === 400, JSON.stringify(mismatch.body));

// 8i. Hardening
const rawPost = async (path, body, type = "application/json") => {
  const r = await fetch(BASE + path, { method: "POST", headers: { "content-type": type }, body });
  let j = null; try { j = await r.json(); } catch {}
  return { status: r.status, body: j };
};
const okFields = async () => { const n = hex(webcrypto.getRandomValues(new Uint8Array(16))); return { uid: randomUUID(), nonce: n, commitment: await commit(k, n), commitV: 2, mode: "manual", placeMode: "none" }; };
check("non-JSON content type is refused (415)", (await rawPost("/api/entries", "{}", "text/plain")).status === 415);
check("oversized body is refused (413)", (await rawPost("/api/entries", JSON.stringify({ text: "x".repeat(150_000) }))).status === 413);
const f1 = await okFields();
check("right-to-left override in text is refused",
  (await rawPost("/api/entries", JSON.stringify({ ticket: await newTicket(), ...f1, title: "t", text: "pay ‮txet" }))).status === 400);
const f2 = await okFields();
check("direction isolate in title is refused",
  (await rawPost("/api/entries", JSON.stringify({ ticket: await newTicket(), ...f2, title: "t⁦", text: "hello" }))).status === 400);
const f3 = await okFields();
check("control character in text is refused",
  (await rawPost("/api/entries", JSON.stringify({ ticket: await newTicket(), ...f3, title: "t", text: "a\u0000b" }))).status === 400);
const f4 = await okFields();
const emoji = await rawPost("/api/entries", JSON.stringify({ ticket: await newTicket(), ...f4, title: "Emoji ok", text: "hello \u{1F600} مرحبا" }));
check("emoji and Arabic text are still accepted", emoji.status === 201, JSON.stringify(emoji.body));
const spoof = await fetch(BASE + "/api/chain", { headers: { "x-forwarded-for": "1.2.3.4" } });
check("chain endpoint answers", spoof.status === 200);
const hdr = await fetch(BASE + "/record");
check("security headers are set",
  hdr.headers.get("x-content-type-options") === "nosniff" &&
  hdr.headers.get("x-frame-options") === "DENY" &&
  (hdr.headers.get("content-security-policy") ?? "").includes("frame-ancestors 'none'"));
check("API responses are not cacheable", (await fetch(BASE + "/api/entries?limit=1")).headers.get("cache-control") === "no-store");

// 9. Chain integrity
const chain = (await api("GET", "/api/chain")).body;
check("hash chain verifies", chain?.ok === true, JSON.stringify(chain));

console.log("\nWaiting ~36s for the locked reveal and the deadline...");
await sleep(Math.max(0, Math.max(t, hpAt) - Date.now()) + 2000);

const after = (await api("GET", `/api/entries/${l.uid}`)).body?.entry;
check("locked entry revealed itself on schedule", after?.status === "revealed" && after.handle === "Locked Lou", JSON.stringify(after));
check("locked reveal time equals the scheduled time", after?.revealedAt === t);
check("after reveal, the hidden schedule is opened and verifies",
  after?.schedule && after.revealAt === t &&
  sha256(JSON.stringify([after.schedule.revealAt, after.schedule.deadlineAt, after.schedule.salt])) === after.schedCommit);
const hpAfter = (await api("GET", `/api/entries/${hp.uid}`)).body?.entry;
check("hidden place opens on its date", hpAfter?.status === "revealed" && hpAfter.place?.label === "Tower" && hpAfter.placeHidden === false, JSON.stringify(hpAfter));
const dd = (await api("GET", `/api/entries/${d.uid}`)).body?.entry;
check("past-deadline unrevealed entry is Unknown", dd?.status === "unknown", JSON.stringify(dd?.status));

// 10. Lists
const unk = (await api("GET", "/api/entries?status=unknown")).body?.entries ?? [];
check("Unknown list contains it", unk.some((e) => e.uid === d.uid));
const rev = (await api("GET", "/api/entries?status=revealed")).body?.entries ?? [];
check("Revealed list contains both revealed entries", rev.some((e) => e.uid === a.uid) && rev.some((e) => e.uid === l.uid));
const chain2 = (await api("GET", "/api/chain")).body;
check("hash chain still verifies", chain2?.ok === true);

// 11. Early reveal of a dated entry uses the sealed name, whatever name is sent
const early2 = await seal(k, { title: "Dated early", mode: "date", revealAt: Date.now() + 3_600_000, handle: "Sealed Sam" });
const er = await api("POST", `/api/entries/${early2.uid}/reveal`, await opening(k, early2.uid, early2.nonce, "Different Alex"));
check("early reveal of dated entry keeps the sealed name", er.status === 200 && er.body?.entry?.handle === "Sealed Sam", JSON.stringify(er.body));
const erOther = await seal(k, { title: "Dated other key", mode: "date", revealAt: Date.now() + 3_600_000, handle: "Owner" });
const erBad = await api("POST", `/api/entries/${erOther.uid}/reveal`, await opening(other, erOther.uid, erOther.nonce, "Owner"));
check("early reveal with the wrong key is still refused", erBad.status === 403);

// 12. Likes and dislikes
const vt = (n) => n.toString(16).padStart(64, "0");
const v1 = await seal(k, { title: "Vote target" });
const v2 = await seal(k, { title: "Vote other" });
const vote = (uid, voter, value) => api("POST", `/api/entries/${uid}/vote`, { voter, value });
let vr = await vote(v1.uid, vt(1), 1);
check("like counts", vr.status === 200 && vr.body.up === 1 && vr.body.down === 0, JSON.stringify(vr.body));
vr = await vote(v1.uid, vt(1), 1);
check("liking twice from one browser still counts once", vr.body?.up === 1);
vr = await vote(v1.uid, vt(1), -1);
check("switching to dislike moves the vote", vr.body?.up === 0 && vr.body?.down === 1);
vr = await vote(v1.uid, vt(1), 0);
check("clearing a vote removes it", vr.body?.up === 0 && vr.body?.down === 0);
await vote(v1.uid, vt(2), 1); await vote(v1.uid, vt(3), 1); await vote(v1.uid, vt(5), 1); await vote(v1.uid, vt(6), 1);
await vote(v2.uid, vt(2), -1);
check("bad vote value refused", (await vote(v1.uid, vt(4), 5)).status === 400);
check("bad voter token refused", (await vote(v1.uid, "nope", 1)).status === 400);
check("vote on missing entry is 404", (await vote(randomUUID(), vt(4), 1)).status === 404);
const topList = (await api("GET", "/api/entries?sort=top&limit=100")).body?.entries ?? [];
const pos = (u) => topList.findIndex((e) => e.uid === u);
check("liked entry ranks first in top", pos(v1.uid) === 0, String(pos(v1.uid)));
check("disliked entry ranks last in top", pos(v2.uid) === topList.length - 1, `${pos(v2.uid)}/${topList.length}`);
check("vote counts are public on the entry", topList[0]?.likes === 4);
const chain3 = (await api("GET", "/api/chain")).body;
check("votes don't affect the hash chain", chain3?.ok === true);
const home = await fetch(`${BASE}/`);
check("record is the landing page", home.status === 200 && (await home.text()).includes("Popular posts"));
const old = await fetch(`${BASE}/record?status=revealed`, { redirect: "manual" });
check("old /record address redirects to /new", [307, 308].includes(old.status) && (old.headers.get("location") || "").includes("/new?status=revealed"), old.status + " " + old.headers.get("location"));
check("seal page is at /say", (await fetch(`${BASE}/say`)).status === 200);

// 13. Comments: permanent, chained, validated, paginated
const ce = await seal(k, { title: "Comment target" });
const rtag = () => b64u(webcrypto.getRandomValues(new Uint8Array(92)));
const comment = (entryUid, body) => api("POST", `/api/entries/${entryUid}/comments`, body);
let cr = await comment(ce.uid, { uid: randomUUID(), text: "  First comment  ", tag: rtag() });
check("comment posted (201)", cr.status === 201 && cr.body?.comment?.text === "First comment", JSON.stringify(cr.body));
const firstC = cr.body?.comment;
check("duplicate comment id refused (409)", (await comment(ce.uid, { uid: firstC.uid, text: "again", tag: rtag() })).status === 409);
check("empty comment refused", (await comment(ce.uid, { uid: randomUUID(), text: "   ", tag: rtag() })).status === 400);
check("over-long comment refused", (await comment(ce.uid, { uid: randomUUID(), text: "x".repeat(2001), tag: rtag() })).status === 400);
check("hidden control characters in a comment refused", (await comment(ce.uid, { uid: randomUUID(), text: "pay ‮txet", tag: rtag() })).status === 400);
check("short tag refused", (await comment(ce.uid, { uid: randomUUID(), text: "hi", tag: "abc" })).status === 400);
const ncTag = rtag().slice(0, 122) + "B"; // last char carries non-zero padding bits
check("non-canonical tag refused", (await comment(ce.uid, { uid: randomUUID(), text: "hi", tag: ncTag })).status === 400);
check("bad comment id refused", (await comment(ce.uid, { uid: "not-a-uuid", text: "hi", tag: rtag() })).status === 400);
check("comment on missing entry is 404", (await comment(randomUUID(), { uid: randomUUID(), text: "hi", tag: rtag() })).status === 404);
check("comment on a malformed entry id is 404", (await comment("../../etc", { uid: randomUUID(), text: "hi", tag: rtag() })).status === 404);
for (let i = 0; i < 54; i++) await comment(ce.uid, { uid: randomUUID(), text: `bulk ${i}`, tag: rtag() });
const p1 = (await api("GET", `/api/entries/${ce.uid}/comments`)).body;
check("comments page 1 has 50 and says there are more", p1?.comments?.length === 50 && p1.more === true, `${p1?.comments?.length} ${p1?.more}`);
const p2 = (await api("GET", `/api/entries/${ce.uid}/comments?after=${p1.comments[49].id}`)).body;
check("comments page 2 has the remaining 5", p2?.comments?.length === 5 && p2.more === false, `${p2?.comments?.length} ${p2?.more}`);
check("comments come oldest first", p1.comments[0].uid === firstC.uid);
const ceAfter = (await api("GET", `/api/entries/${ce.uid}`)).body?.entry;
check("entry shows its comment count", ceAfter?.commentCount === 55, String(ceAfter?.commentCount));

// 14. Private follow-up links: derive exactly as the browser does
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
async function hm(key, label) {
  const hk = await subtle.importKey("raw", Buffer.from(key.priv.d, "base64url"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", hk, enc.encode(label)));
}
async function thread(key, nonce) {
  const encKey = await hm(key, `whenisaid:thread-enc:v1:${nonce}`);
  const seed = await hm(key, `whenisaid:thread-sign:v1:${nonce}`);
  const sk = await subtle.importKey("pkcs8", Buffer.concat([PKCS8, seed]), { name: "Ed25519" }, true, ["sign"]);
  const pub = (await subtle.exportKey("jwk", sk)).x;
  return { encKey, pub, sk };
}
const cmsg = (e, c, t) => enc.encode(`whenisaid:comment:v1:${e}:${c}:${t}`);
async function sealTag(encKey, sig) {
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const aes = await subtle.importKey("raw", encKey, { name: "AES-GCM" }, false, ["encrypt"]);
  return b64u(Buffer.concat([iv, Buffer.from(await subtle.encrypt({ name: "AES-GCM", iv }, aes, sig))]));
}
async function holderSees(encKey, pubX, entryUid, c) {
  try {
    const raw = Buffer.from(c.tag, "base64url");
    const aes = await subtle.importKey("raw", encKey, { name: "AES-GCM" }, false, ["decrypt"]);
    const sig = await subtle.decrypt({ name: "AES-GCM", iv: raw.subarray(0, 12) }, aes, raw.subarray(12));
    const pk = await subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: pubX }, { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify({ name: "Ed25519" }, pk, sig, cmsg(entryUid, c.uid, c.text));
  } catch { return false; }
}
const th = await thread(k, ce.nonce);
const aUid = randomUUID();
const aText = "Follow-up from the source";
const aTag = await sealTag(th.encKey, await subtle.sign({ name: "Ed25519" }, th.sk, cmsg(ce.uid, aUid, aText)));
const ac = await comment(ce.uid, { uid: aUid, text: aText, tag: aTag });
check("author follow-up accepted like any comment", ac.status === 201, JSON.stringify(ac.body));
check("link holder recognises the author's follow-up", await holderSees(th.encKey, th.pub, ce.uid, ac.body.comment));
check("link holder does not mark ordinary comments", !(await holderSees(th.encKey, th.pub, ce.uid, firstC)));
const th2 = await thread(k, ce.nonce);
check("thread key is reproducible from the key backup", th2.pub === th.pub && Buffer.compare(th2.encKey, th.encKey) === 0);
const otherEntryThread = await thread(k, (await seal(k, { title: "Other entry" })).nonce);
check("same author's threads on different entries are unlinked", otherEntryThread.pub !== th.pub);
check("another entry's link doesn't recognise this follow-up", !(await holderSees(otherEntryThread.encKey, otherEntryThread.pub, ce.uid, ac.body.comment)));
// A link holder has encKey but not the signing key: a forged follow-up must not verify.
const forger = await subtle.generateKey({ name: "Ed25519" }, true, ["sign"]);
const fUid = randomUUID();
const fTag = await sealTag(th.encKey, await subtle.sign({ name: "Ed25519" }, forger.privateKey, cmsg(ce.uid, fUid, "Fake source")));
const fc = await comment(ce.uid, { uid: fUid, text: "Fake source", tag: fTag });
check("link holder can't forge the author", fc.status === 201 && !(await holderSees(th.encKey, th.pub, ce.uid, fc.body.comment)));
check("author tag can't be moved onto different text", !(await holderSees(th.encKey, th.pub, ce.uid, { ...ac.body.comment, text: "Edited" })));
const pubJson = JSON.stringify((await api("GET", `/api/entries/${ce.uid}/comments?after=50`)).body);
check("nothing in the public comment data names the author's key", !pubJson.includes(th.pub) && !pubJson.includes(k.pub.x));

// 15. Did it happen? (revealed entries only) and Came true
const oEnt = await seal(k, { title: "Outcome target" });
const outcome = (uid, voter, value) => api("POST", `/api/entries/${uid}/outcome`, { voter, value });
check("can't vote on the outcome before reveal (409)", (await outcome(oEnt.uid, vt(1), 1)).status === 409);
await api("POST", `/api/entries/${oEnt.uid}/reveal`, await opening(k, oEnt.uid, oEnt.nonce, "Outcome Olly"));
let orr = await outcome(oEnt.uid, vt(1), 1);
check("outcome vote counts after reveal", orr.status === 200 && orr.body.up === 1 && orr.body.down === 0, JSON.stringify(orr.body));
await outcome(oEnt.uid, vt(2), 1); await outcome(oEnt.uid, vt(3), -1);
orr = await outcome(oEnt.uid, vt(3), -1);
check("one outcome vote per browser", orr.body?.up === 2 && orr.body?.down === 1, JSON.stringify(orr.body));
check("outcome vote on missing entry is 404", (await outcome(randomUUID(), vt(1), 1)).status === 404);
check("outcome and like votes are separate", (await api("GET", `/api/entries/${oEnt.uid}`)).body?.entry?.likes === 0);
const calledHtml = await (await fetch(`${BASE}/called`)).text();
check("Came true page lists the voted entry", calledHtml.includes("Outcome target"));
check("Came true page 2 is empty but works", (await fetch(`${BASE}/called?page=2`)).status === 200);
check("Came true ignores silly page numbers", (await fetch(`${BASE}/called?page=-5`)).status === 200 && (await fetch(`${BASE}/called?page=99999999`)).status === 200);
const chain4 = (await api("GET", "/api/chain")).body;
check("comment chain verifies and is counted", chain4?.ok === true && chain4?.comments?.ok === true && chain4.comments.count >= 57, JSON.stringify(chain4?.comments));
const entryHtml = await (await fetch(`${BASE}/e/${ce.uid}`)).text();
check("entry page shows comments", entryHtml.includes("First comment") && entryHtml.includes("Show more comments"));

// 16. Spam: door rules (refused posts are never recorded)
const se = await seal(k, { title: "Spam target one", text: `first quiet entry ${randomUUID()}` });
const se2 = await seal(k, { title: "Spam target two", text: `second quiet entry ${randomUUID()}` });
const se3 = await seal(k, { title: "Spam target three", text: `third quiet entry ${randomUUID()}` });
const noTicket = await rawPost(`/api/entries/${se.uid}/comments`, JSON.stringify({ uid: randomUUID(), text: "no ticket", tag: rtag() }));
check("comment without a form ticket is refused (428)", noTicket.status === 428);
const badTicket = await rawPost(`/api/entries/${se.uid}/comments`, JSON.stringify({ uid: randomUUID(), text: "bad ticket", tag: rtag(), ticket: `${Date.now()}.forged` }));
check("forged ticket is refused (428)", badTicket.status === 428);
const f5 = await okFields();
check("entry without a form ticket is refused (428)", (await rawPost("/api/entries", JSON.stringify({ ...f5, title: "t", text: "no ticket here" }))).status === 428);
const trapped = await rawPost(`/api/entries/${se.uid}/comments`, JSON.stringify({ uid: randomUUID(), text: "bot", tag: rtag(), ticket: await newTicket(), website: "http://x.example" }));
check("filled-in hidden field is refused", trapped.status === 400);
check("comment with too many links is refused", (await comment(se.uid, { uid: randomUUID(), text: "a http://a.example b http://b.example c http://c.example", tag: rtag() })).status === 400);
const f6 = await okFields();
check("entry with too many links is refused", (await rawPost("/api/entries", JSON.stringify({ ticket: await newTicket(), ...f6, title: "t", text: Array.from({ length: 6 }, (_, i) => `http://l${i}.example`).join(" ") }))).status === 400);
const twin = `identical entry text for the duplicate rule ${randomUUID()}`;
check("identical entry within a day is refused (409)", (await seal(k, { title: "Twin", text: twin })).res.status === 201 && (await seal(k, { title: "Twin", text: twin })).res.status === 409);

// 17. Spam: repeated comment text is refused; nothing already posted is removed
const pitch = `Great opportunity, message me about this amazing offer ${randomUUID()}`;
const m1 = await comment(se.uid, { uid: randomUUID(), text: pitch, tag: rtag() });
check("first copy of a comment is accepted", m1.status === 201);
check("same text again on the same entry is refused", (await comment(se.uid, { uid: randomUUID(), text: pitch.toUpperCase() + "!!", tag: rtag() })).status === 400);
const m2 = await comment(se2.uid, { uid: randomUUID(), text: pitch, tag: rtag() });
check("a second entry may carry the same text", m2.status === 201);
check("third entry with the same text is refused", (await comment(se3.uid, { uid: randomUUID(), text: pitch, tag: rtag() })).status === 400);
const swept = (await api("GET", `/api/entries/${se.uid}/comments`)).body?.comments?.find((c) => c.uid === m1.body.comment.uid);
check("earlier copies are never removed automatically", swept?.removed === false && swept.text === pitch && swept.textHash === sha256(pitch), JSON.stringify(swept));
check("short comments may repeat freely", (await comment(se.uid, { uid: randomUUID(), text: "Agreed", tag: rtag() })).status === 201 && (await comment(se.uid, { uid: randomUUID(), text: "Agreed", tag: rtag() })).status === 201);

// 18. Spam flags: counted in public, never hide or remove, and sink an entry's rank exponentially
const rc = (await comment(se.uid, { uid: randomUUID(), text: "A comment some readers will flag", tag: rtag() })).body.comment;
const reportC = (id, voter) => api("POST", `/api/comments/${id}/report`, { voter });
let rr = await reportC(rc.id, vt(1));
check("spam flag recorded", rr.status === 200 && rr.body.reports === 1 && !("collapsed" in rr.body), JSON.stringify(rr.body));
rr = await reportC(rc.id, vt(1));
check("one spam flag per browser", rr.body?.reports === 1);
for (let i = 2; i < 40; i++) await reportC(rc.id, vt(i));
const stillThere = (await api("GET", `/api/entries/${se.uid}/comments`)).body?.comments?.find((c) => c.uid === rc.uid);
check("any number of flags never hides or removes a comment", stillThere?.reports === 39 && stillThere.removed === false && stillThere.text === rc.text && !("collapsed" in stillThere), JSON.stringify(stillThere));
check("flag on a missing comment is 404", (await reportC(99999999, vt(1))).status === 404 && (await reportC("abc", vt(1))).status === 404);
const reportE = (uid, voter) => api("POST", `/api/entries/${uid}/report`, { voter });
const like = (uid, n, base) => Promise.all(Array.from({ length: n }, (_, i) => api("POST", `/api/entries/${uid}/vote`, { voter: vt(base + i), value: 1 })));
const topUids = async () => ((await api("GET", "/api/entries?sort=top&limit=100")).body?.entries ?? []).map((e) => e.uid);
const rankOf = (list, e) => list.indexOf(e.uid);
// se2: 6 likes; se3: 4 likes. Unflagged, se2 leads.
await like(se2.uid, 6, 300); await like(se3.uid, 4, 320);
let top = await topUids();
check("unflagged, the better liked entry ranks higher", rankOf(top, se2) >= 0 && rankOf(top, se2) < rankOf(top, se3), `${rankOf(top, se2)} ${rankOf(top, se3)}`);
await reportE(se2.uid, vt(1));
top = await topUids();
check("one flag costs one like (6 - 1 still beats 4)", rankOf(top, se2) < rankOf(top, se3));
let er2 = await reportE(se2.uid, vt(2));
check("flag count is returned, with no delisting", er2.status === 200 && er2.body.reports === 2 && !("delisted" in er2.body), JSON.stringify(er2.body));
top = await topUids();
check("two flags cost three likes (6 - 3 falls behind 4)", rankOf(top, se3) < rankOf(top, se2), `${rankOf(top, se2)} ${rankOf(top, se3)}`);
for (let i = 3; i <= 12; i++) await reportE(se2.uid, vt(i));
top = await topUids();
check("a heavily flagged entry sinks below unvoted ones but stays listed", rankOf(top, se2) > rankOf(top, se) && rankOf(top, se) >= 0, `${rankOf(top, se2)} ${rankOf(top, se)}`);
const flagged = (await api("GET", `/api/entries/${se2.uid}`)).body?.entry;
check("flagged entry shows its count and is not delisted", flagged?.reports === 12 && flagged.delisted === false && flagged.text.length > 0, JSON.stringify(flagged?.reports));
check("flagged entry is still on the New list", ((await api("GET", "/api/entries?limit=100")).body?.entries ?? []).some((e) => e.uid === se2.uid));
for (let i = 13; i <= 60; i++) await reportE(se2.uid, vt(i));
check("the penalty is capped, so huge flag counts still list cleanly", (await topUids()).includes(se2.uid));

// 18b. Tickets work once; flags need one; limits group IPv6 by /64
{
  const T = await newTicket();
  const body = (txt) => JSON.stringify({ uid: randomUUID(), text: txt, tag: rtag(), ticket: T });
  const first = await rawPost(`/api/entries/${se.uid}/comments`, body("A comment that spends the ticket"));
  const again = await rawPost(`/api/entries/${se.uid}/comments`, body("A second comment with the same ticket"));
  check("a ticket works once", first.status === 201 && again.status === 428, `${first.status} ${again.status}`);
  const noTicket = await rawPost(`/api/entries/${se.uid}/report`, JSON.stringify({ voter: vt(900) }));
  check("a spam flag without a ticket is refused", noTicket.status === 428, JSON.stringify(noTicket.body));
  const trapFlag = await rawPost(`/api/entries/${se.uid}/report`, JSON.stringify({ voter: vt(901), ticket: await newTicket(), website: "x" }));
  check("a spam flag that fills the hidden field is refused", trapFlag.status === 400);
  const { groupV6 } = await import("../src/lib/ip.ts");
  check("IPv4 addresses are left alone", groupV6("203.0.113.9") === "203.0.113.9" && groupV6("::ffff:203.0.113.9") === "203.0.113.9");
  check("an IPv6 address is limited as its /64", groupV6("2001:db8:1:2:aaaa:bbbb:cccc:dddd") === groupV6("2001:0db8:0001:0002::1") && groupV6("2001:db8:1:2:a::1") === "2001:db8:1:2::/64");
  check("different /64s stay separate, and bad input is returned as it was", groupV6("2001:db8:1:3::1") !== groupV6("2001:db8:1:2::1") && groupV6("unknown") === "unknown" && groupV6("1:2:3") === "1:2:3");
}

// 19. Similar entries are grouped; the best ranked one represents the group
const topic = `The council will approve the harbour bridge project before the autumn election ${randomUUID().slice(0, 8)}`;
const g1 = await seal(k, { title: "Bridge approval", text: topic });
const g2 = await seal(k, { title: "Bridge approval soon", text: topic.replace("approve", "certainly approve") });
const g3 = await seal(k, { title: "Bridge approval coming", text: topic.replace("autumn", "next autumn") });
const lone = await seal(k, { title: "Unrelated weather note", text: `Heavy snowfall expected across northern valleys tomorrow ${randomUUID()}` });
check("similar entries all sealed", [g1, g2, g3, lone].every((x) => x.res.status === 201));
const ge = async (x) => (await api("GET", `/api/entries/${x.uid}`)).body?.entry;
check("each sees the other two as similar", (await ge(g1))?.similar === 2 && (await ge(g2))?.similar === 2 && (await ge(g3))?.similar === 2);
check("an unrelated entry has no similar entries", (await ge(lone))?.similar === 0);
await api("POST", `/api/entries/${g2.uid}/vote`, { voter: vt(1), value: 1 });
await api("POST", `/api/entries/${g2.uid}/vote`, { voter: vt(2), value: 1 });
const topNow = (await api("GET", "/api/entries?sort=top&limit=100")).body?.entries ?? [];
const inTop = [g1, g2, g3].filter((x) => topNow.some((e) => e.uid === x.uid));
check("top shows a group once, by its best ranked entry", inTop.length === 1 && inTop[0].uid === g2.uid, inTop.map((x) => x.uid).join());
const newNow = (await api("GET", "/api/entries?limit=100")).body?.entries ?? [];
check("new still lists every entry in the group", [g1, g2, g3].every((x) => newNow.some((e) => e.uid === x.uid)));
const simHtml = await (await fetch(`${BASE}/similar/${g1.uid}`)).text();
check("similar page links the others, best ranked first", simHtml.includes("Bridge approval soon") && simHtml.includes("Bridge approval coming") && simHtml.indexOf("Bridge approval soon") < simHtml.indexOf("Bridge approval coming"));
check("similar page for a missing entry is 404", (await fetch(`${BASE}/similar/${randomUUID()}`)).status === 404);
check("entry page shows its similar entries", (await (await fetch(`${BASE}/e/${g1.uid}`)).text()).includes("Similar entries"));

// 19b. Private chat: the server counts link uses, guards rooms, and never sees a key
const CC = await import("../src/lib/chat-crypto.ts");
const KK = await import("../src/lib/client-crypto.ts");
const chatApi = async (method, path, body, headers = {}) => {
  const res = await fetch(BASE + path, { method, headers: { ...(body ? { "content-type": "application/json" } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, body: await res.json().catch(() => null) };
};
const mkInvite = async (maxUses, extra = {}) => {
  const inv = await CC.newInvite(maxUses);
  const res = await chatApi("POST", "/api/chat/invites", { id: inv.id, owner: inv.ownerHash, hello: inv.hello, maxUses, ticket: await newTicket(), ...extra });
  return { inv, res };
};
const joinChat = async (inv) => {
  const h = await chatApi("GET", `/api/chat/invites/${inv.id}`);
  if (!h.body?.open) return { hello: h, res: { status: 410 } };
  const j = await CC.joinWith(inv.secret, h.body.hello, h.body.slot);
  const res = await chatApi("POST", `/api/chat/invites/${inv.id}/join`, { room: j.roomId, join: j.join, auth: j.authHash, slot: h.body.slot });
  return { hello: h, j, res, slot: h.body.slot, keys: await CC.roomKeys(j.master, j.roomId) };
};
const once = await mkInvite(1);
check("chat link created", once.res.status === 201, JSON.stringify(once.res));
check("chat link needs a form ticket", (await chatApi("POST", "/api/chat/invites", { id: "a".repeat(64), owner: "b".repeat(64), hello: once.inv.hello, maxUses: 1 })).status === 428);
check("chat link refuses the hidden trap field", (await mkInvite(1, { website: "x" })).res.status === 400);
check("same link can't be registered twice", (await chatApi("POST", "/api/chat/invites", { id: once.inv.id, owner: once.inv.ownerHash, hello: once.inv.hello, maxUses: 1, ticket: await newTicket() })).status === 409);
check("link secret never reaches the server", !JSON.stringify([once.inv.id, once.inv.ownerHash, once.inv.hello]).includes(once.inv.secret));
check("unknown link is 404", (await chatApi("GET", `/api/chat/invites/${"0".repeat(64)}`)).status === 404);
const bj = await joinChat(once.inv);
check("opening the link creates a room", bj.res.status === 201 && bj.hello.body.open === true, JSON.stringify(bj.res));
const second = await CC.joinWith(once.inv.secret, bj.hello.body.hello, 0);
const secondRes = await chatApi("POST", `/api/chat/invites/${once.inv.id}/join`, { room: second.roomId, join: second.join, auth: second.authHash, slot: 0 });
check("a one-time link can't be opened twice", secondRes.status === 410 && (await chatApi("GET", `/api/chat/invites/${once.inv.id}`)).body?.open === false, JSON.stringify(secondRes));
check("join list needs the creator's secret", (await chatApi("GET", `/api/chat/invites/${once.inv.id}`, null, { "x-chat-owner": "f".repeat(64) })).status === 404);
const status = (await chatApi("GET", `/api/chat/invites/${once.inv.id}`, null, { "x-chat-owner": once.inv.ownerSecret })).body;
check("creator sees exactly one joiner, in the first place", status?.uses === 1 && status.rooms.length === 1 && status.rooms[0].id === bj.j.roomId && status.rooms[0].slot === 0, JSON.stringify(status));
const aMaster = (await CC.acceptJoin(once.inv.secret, once.inv.privs[0], status.rooms[0].id, status.rooms[0].join, status.rooms[0].slot))?.master;
check("creator derives the same key from what the server relays", aMaster === bj.j.master);
const aKeys = await CC.roomKeys(aMaster, bj.j.roomId);
const roomUrl = `/api/chat/rooms/${bj.j.roomId}`;
const A = { "x-chat-auth": aKeys.token };
check("room is closed without its token", (await chatApi("GET", roomUrl)).status === 404 && (await chatApi("GET", roomUrl, null, { "x-chat-auth": "0".repeat(64) })).status === 404);
check("posting needs the token", (await chatApi("POST", roomUrl, { blob: "A".repeat(100) })).status === 404);
const secretText = `the meeting is at dawn ${randomUUID()}`;
const sentMsg = await chatApi("POST", roomUrl, { blob: await CC.encryptMessage(aKeys, bj.j.roomId, "a", 0, { kind: "text", text: secretText }) }, A);
check("message stored", sentMsg.status === 201 && sentMsg.body.id > 0);
await chatApi("POST", roomUrl, { blob: await CC.encryptMessage(bj.keys, bj.j.roomId, "b", 0, { kind: "text", text: "understood" }) }, { "x-chat-auth": bj.keys.token });
const got = (await chatApi("GET", roomUrl, null, { "x-chat-auth": bj.keys.token })).body;
check("server hands back only ciphertext", got?.messages?.length === 2 && !JSON.stringify(got).includes("dawn") && got.ttl === 0);
const plain0 = await CC.decryptMessage(bj.keys, bj.j.roomId, got.messages[0].blob);
check("the other side decrypts it", plain0?.text === secretText && plain0.from === "a" && plain0.n === 0);
check("paging by ?after works", (await chatApi("GET", `${roomUrl}?after=${got.messages[0].id}`, null, A)).body?.messages?.length === 1);
check("oversized or malformed blobs are refused", (await chatApi("POST", roomUrl, { blob: "A".repeat(46001) }, A)).status === 400 && (await chatApi("POST", roomUrl, { blob: "not base64 !!".repeat(4) }, A)).status === 400 && (await chatApi("POST", roomUrl, { blob: 5 }, A)).status === 400);
// Source introduces themselves and proves a public post, with the keys the browser makes.
const idk = await CC.chatIdentity(Buffer.from(k.priv.d, "base64url"), bj.j.roomId);
const idSig = await CC.signIdentity(idk.sign, bj.j.roomId, aKeys.bind);
check("source's chat identity verifies for the other side", await CC.verifyIdentity(idk.pubX, idSig, bj.j.roomId, bj.keys.bind));
const provedEntry = (await api("GET", `/api/entries/${se.uid}`)).body.entry;
const pek = await KK.entryKey(k, provedEntry.nonce), psalt = await KK.deriveSaltV2(k, provedEntry.nonce);
check("a sealed entry is proved to the chat partner", provedEntry.commitV === 2 && await CC.proofMatches(pek.pubX, psalt, provedEntry, provedEntry.commitment));
check("the proof carries a key that isn't the chat identity or shared with other entries", pek.pubX !== idk.pubX && pek.pubX !== (await KK.entryKey(k, (await api("GET", `/api/entries/${oEnt.uid}`)).body.entry.nonce)).pubX);
check("a proof for one entry does not fit another", !(await CC.proofMatches(pek.pubX, psalt, provedEntry, (await api("GET", `/api/entries/${oEnt.uid}`)).body.entry.commitment)));
check("the site can't make an entry's text say something else and still verify", !(await CC.proofMatches(pek.pubX, psalt, { ...provedEntry, text: "Words the author never wrote" }, provedEntry.commitment)));
check("a place a second opener wanted is already taken", (await chatApi("POST", `/api/chat/invites/${once.inv.id}/join`, { room: randomUUID(), join: "A".repeat(100), auth: "a".repeat(64), slot: 0 })).status === 410);
check("timer accepts only the offered values", (await chatApi("PATCH", roomUrl, { ttl: 1234 }, A)).status === 400 && (await chatApi("PATCH", roomUrl, { ttl: 86_400_000 }, A)).body?.ttl === 86_400_000);
check("timer shows for both sides", (await chatApi("GET", roomUrl, null, { "x-chat-auth": bj.keys.token })).body?.ttl === 86_400_000);
const multi = await mkInvite(2);
const mj1 = await joinChat(multi.inv), mj2 = await joinChat(multi.inv), mj3 = await joinChat(multi.inv);
check("a two-use link opens twice, each in its own room, then closes", mj1.res.status === 201 && mj2.res.status === 201 && mj3.res.status === 410 && mj1.j.roomId !== mj2.j.roomId && mj1.j.master !== mj2.j.master);
check("each opening gets its own creator key", mj1.slot === 0 && mj2.slot === 1);
{
  const st2 = (await chatApi("GET", `/api/chat/invites/${multi.inv.id}`, null, { "x-chat-owner": multi.inv.ownerSecret })).body;
  const m0 = (await CC.acceptJoin(multi.inv.secret, multi.inv.privs[0], st2.rooms[0].id, st2.rooms[0].join, 0))?.master;
  const m1 = (await CC.acceptJoin(multi.inv.secret, multi.inv.privs[1], st2.rooms[1].id, st2.rooms[1].join, 1))?.master;
  check("the creator derives each room's own key from its own private key", m0 === mj1.j.master && m1 === mj2.j.master);
  const forgedSlot = await chatApi("POST", `/api/chat/invites/${(await mkInvite(2)).inv.id}/join`, { room: randomUUID(), join: "A".repeat(100), auth: "a".repeat(64), slot: 5 });
  check("a place beyond what the link was made for is refused", forgedSlot.status === 400, JSON.stringify(forgedSlot.body));
  const fresh2 = await mkInvite(3);
  const hh = (await chatApi("GET", `/api/chat/invites/${fresh2.inv.id}`)).body;
  const ja = await CC.joinWith(fresh2.inv.secret, hh.hello, 1), jb = await CC.joinWith(fresh2.inv.secret, hh.hello, 1);
  const ra = await chatApi("POST", `/api/chat/invites/${fresh2.inv.id}/join`, { room: ja.roomId, join: ja.join, auth: ja.authHash, slot: 1 });
  const rb = await chatApi("POST", `/api/chat/invites/${fresh2.inv.id}/join`, { room: jb.roomId, join: jb.join, auth: jb.authHash, slot: 1 });
  check("two people can't take the same place on a link", ra.status === 201 && rb.status === 409, `${ra.status} ${rb.status}`);
  check("the next free place moves on", (await chatApi("GET", `/api/chat/invites/${fresh2.inv.id}`)).body?.slot === 0);
}
check("one joiner can't read another's room", (await chatApi("GET", `/api/chat/rooms/${mj2.j.roomId}`, null, { "x-chat-auth": mj1.keys.token })).status === 404);
const open = await mkInvite(0);
check("an 'as many as allowed' link keeps opening", (await joinChat(open.inv)).res.status === 201 && (await joinChat(open.inv)).res.status === 201 && (await joinChat(open.inv)).res.status === 201);
check("only the creator can cancel a link", (await chatApi("DELETE", `/api/chat/invites/${open.inv.id}`, null, { "x-chat-owner": "1".repeat(64) })).status === 404 && (await chatApi("DELETE", `/api/chat/invites/${open.inv.id}`, null, { "x-chat-owner": open.inv.ownerSecret })).status === 200);
check("a cancelled link can't be opened", (await joinChat(open.inv)).res.status === 410);
check("bad link limits are refused", (await mkInvite(-1)).res.status === 400 && (await mkInvite(1.5)).res.status === 400 && (await mkInvite(5000)).res.status === 400 && (await mkInvite(101)).res.status === 400);
const delRoom = `/api/chat/rooms/${mj1.j.roomId}`, D = { "x-chat-auth": mj1.keys.token };
await chatApi("POST", delRoom, { blob: await CC.encryptMessage(mj1.keys, mj1.j.roomId, "b", 0, { kind: "text", text: "to be deleted" }) }, D);
check("deleting a chat needs the token", (await chatApi("DELETE", delRoom)).status === 404);
check("either side can delete the chat", (await chatApi("DELETE", delRoom, null, D)).status === 200);
check("a deleted chat says so and takes no more messages", (await chatApi("GET", delRoom, null, D)).status === 410 && (await chatApi("POST", delRoom, { blob: "A".repeat(100) }, D)).status === 410);
check("chat page loads", (await fetch(`${BASE}/chat`)).status === 200);

// 20. Admin tool (only when the test runs beside the database)
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
if (existsSync("data/whenisaid.db") && /\/\/(127\.0\.0\.1|localhost)[:/]/.test(BASE + "/")) {
  const admin = (...a) => execFileSync(process.execPath, ["--no-warnings", "scripts/admin.mjs", ...a], { encoding: "utf8" });
  const bad = `pills.bad-${randomUUID().slice(0, 8)}.example`;
  const bc = await comment(se.uid, { uid: randomUUID(), text: `cheap stuff at https://${bad}/buy now`, tag: rtag() });
  const be = await seal(k, { title: "Advert", text: `visit ${bad} for deals ${randomUUID()}` });
  check("unblocked site is accepted at first", bc.status === 201 && be.res.status === 201);
  const out = admin("block", bad);
  check("admin block says earlier posts are untouched", /earlier ones are untouched/.test(out), out);
  const kept = (await api("GET", `/api/entries/${se.uid}/comments?after=${bc.body.comment.id - 1}`)).body?.comments?.[0];
  check("blocking a site leaves earlier comments alone", kept?.removed === false && kept.text.includes(bad));
  check("blocking a site leaves earlier entries listed", (await ge(be))?.delisted === false);
  check("blocked site is refused in new comments", (await comment(se.uid, { uid: randomUUID(), text: `see www.${bad} today`, tag: rtag() })).status === 400);
  check("blocked site is refused in new entries", (await seal(k, { title: "Advert again", text: `go to sub.${bad} ${randomUUID()}` })).res.status === 400);
  const plain = (await comment(se.uid, { uid: randomUUID(), text: "An ordinary comment the admin removes", tag: rtag() })).body.comment;
  admin("remove-comment", String(plain.id));
  const plainNow = (await api("GET", `/api/entries/${se.uid}/comments?after=${plain.id - 1}`)).body?.comments?.[0];
  check("admin can remove a comment's text", plainNow?.removed === true && plainNow.removedReason === "removed by admin");
  admin("delist", se3.uid);
  check("admin can take an entry off the lists by hand", (await ge(se3))?.delisted === true && !(await topUids()).includes(se3.uid));
  admin("relist", se3.uid);
  check("admin can put it back", (await ge(se3))?.delisted === false);
  admin("clear-spam", `c${rc.id}`); admin("clear-spam", se2.uid);
  check("admin can clear spam flags on a comment", (await api("GET", `/api/entries/${se.uid}/comments`)).body?.comments?.find((c) => c.uid === rc.uid)?.reports === 0);
  check("admin can clear spam flags on an entry", (await ge(se2))?.reports === 0);
  // Anchoring: the site signs its tips, and the independent verifier agrees with the site.
  const ran = execFileSync(process.execPath, ["--no-warnings", "scripts/anchor.mjs"], { encoding: "utf8" });
  check("anchoring signs the tips, using no outside service", /Anchored \d+ entries/.test(ran) && !/opentimestamps|bitcoin/i.test(readFileSync("scripts/anchor.mjs", "utf8")), ran);
  const anchors = (await api("GET", "/api/anchors")).body;
  check("anchors are published with the site's key", /^[A-Za-z0-9_-]{43}$/.test(anchors?.publicKey ?? "") && anchors.anchors.length >= 1 && anchors.anchors[0].head.entries.count > 0);
  const head = await (await fetch(`${BASE}/api/anchors/${anchors.anchors[0].id}/head`)).text();
  check("the signed text is served exactly", head === JSON.stringify(anchors.anchors[0].head));
  const ranAgain = execFileSync(process.execPath, ["--no-warnings", "scripts/anchor.mjs"], { encoding: "utf8" });
  check("nothing is anchored twice when nothing changed", /Nothing new/.test(ranAgain));
  let verifyOut = "";
  try { verifyOut = execFileSync(process.execPath, ["--no-warnings", "scripts/verify-log.mjs", BASE], { encoding: "utf8" }); } catch (err) { verifyOut = String(err.stdout || err); }
  check("the standalone verifier recomputes both chains and matches the anchor", /The record is consistent/.test(verifyOut) && /1 of 1 signed anchors match/.test(verifyOut), verifyOut);
  const { DatabaseSync: DB2 } = await import("node:sqlite");
  const adb = new DB2("data/whenisaid.db");
  adb.exec("PRAGMA busy_timeout = 10000;");
  const origTitle = adb.prepare("SELECT title FROM entries WHERE seq = 1").get().title;
  adb.prepare("UPDATE entries SET title = ? WHERE seq = 1").run("Quietly rewritten after it was anchored");
  let tamperOut = "";
  try { execFileSync(process.execPath, ["--no-warnings", "scripts/verify-log.mjs", BASE], { encoding: "utf8" }); } catch (err) { tamperOut = String(err.stdout || err); }
  check("rewriting an anchored entry is caught by the verifier", /problem\(s\) found/.test(tamperOut) && /entry 1:/.test(tamperOut), tamperOut);
  adb.prepare("UPDATE entries SET title = ? WHERE seq = 1").run(origTitle);
  adb.close();
  // Mirror: copies and re-verifies the record, serves it on, and notices a rewritten history.
  {
    const { mkdtempSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { spawn } = await import("node:child_process");
    const run = (args) => { try { return { code: 0, out: execFileSync(process.execPath, ["--no-warnings", "scripts/mirror.mjs", ...args], { encoding: "utf8" }) }; } catch (err) { return { code: err.status, out: String(err.stdout || "") }; } };
    const count = (f) => { try { return readFileSync(f, "utf8").split("\n").filter(Boolean).length; } catch { return -1; } };
    const mdb = new (await import("node:sqlite")).DatabaseSync("data/whenisaid.db");
    mdb.exec("PRAGMA busy_timeout = 10000;");
    const chainNow = (await api("GET", "/api/chain")).body;
    const d1 = mkdtempSync(join(tmpdir(), "mirror-"));
    const r1 = run([BASE, "--dir", d1]);
    check("a mirror copies the whole record and exits cleanly", r1.code === 0 && count(`${d1}/entries.jsonl`) === chainNow.count && count(`${d1}/comments.jsonl`) === chainNow.comments.count, r1.out);
    check("it pins the site's key and keeps the anchors", /Pinned the site's signing key/.test(r1.out) && count(`${d1}/anchors.jsonl`) >= 1);
    const r2 = run([BASE, "--dir", d1, "--full"]);
    check("syncing again, with a full re-check, finds nothing wrong", r2.code === 0 && !/ALERT/.test(r2.out), r2.out);
    // A mirror of a mirror, compared against the original
    const port = 3300 + Math.floor(Math.random() * 500);
    const srv = spawn(process.execPath, ["--no-warnings", "scripts/mirror.mjs", BASE, "--dir", d1, "--serve", String(port)], { stdio: ["ignore", "pipe", "inherit"] });
    await new Promise((res) => { srv.stdout.on("data", (d) => /Serving/.test(String(d)) && res()); setTimeout(res, 15000); });
    const d2 = mkdtempSync(join(tmpdir(), "mirror-"));
    const r3 = run([`http://127.0.0.1:${port}`, "--dir", d2, "--peer", BASE]);
    check("another mirror can copy from a mirror and agrees with the original", r3.code === 0 && count(`${d2}/entries.jsonl`) === chainNow.count && /agrees/.test(r3.out), r3.out);
    check("a mirror serves the same record the site does", JSON.stringify((await (await fetch(`http://127.0.0.1:${port}/api/chain`)).json()).tip) === JSON.stringify(chainNow.tip));
    // The site rewrites its history: the last entry's hash changes.
    const lastSeq = mdb.prepare("SELECT MAX(seq) AS s FROM entries").get().s;
    const oldHash = mdb.prepare("SELECT entry_hash FROM entries WHERE seq = ?").get(lastSeq).entry_hash;
    mdb.prepare("UPDATE entries SET entry_hash = ? WHERE seq = ?").run("f".repeat(64), lastSeq);
    const r4 = run([BASE, "--dir", d1]);
    check("a mirror notices when the site rewrites history, and keeps its own copy", r4.code === 2 && /history-rewritten/.test(r4.out) && count(`${d1}/entries.jsonl`) === chainNow.count, r4.out);
    const r5 = run([`http://127.0.0.1:${port}`, "--dir", d2, "--peer", BASE]);
    check("a peer whose record differs is reported as a fork", r5.code === 2 && /\[fork\]/.test(r5.out), r5.out);
    mdb.prepare("UPDATE entries SET entry_hash = ? WHERE seq = ?").run(oldHash, lastSeq);
    // Changing an old entry's text without touching its hash only shows up with --full.
    const oldTitle = mdb.prepare("SELECT title FROM entries WHERE seq = 1").get().title;
    mdb.prepare("UPDATE entries SET title = ? WHERE seq = 1").run("Changed after the mirror copied it");
    const r6 = run([BASE, "--dir", d1, "--full"]);
    check("a full re-check catches an old entry whose text was changed", r6.code === 2 && /history-rewritten/.test(r6.out) && /entry 1 /.test(r6.out), r6.out);
    mdb.prepare("UPDATE entries SET title = ? WHERE seq = 1").run(oldTitle);
    check("once the site is honest again the mirror is satisfied", run([BASE, "--dir", d1, "--full"]).code === 0);
    // Witnessing: a mirror countersigns the site's anchors, once the operator accepts its key.
    const dw = mkdtempSync(join(tmpdir(), "mirror-"));
    const w1 = run([BASE, "--dir", dw, "--witness"]);
    const wkey = /Witness key: ([A-Za-z0-9_-]{43})/.exec(w1.out)?.[1];
    check("a witness mirror makes its own key and is refused until the operator accepts it", !!wkey && /has not accepted this witness key/.test(w1.out) && w1.code === 0, w1.out);
    check("no witness is shown before that", ((await api("GET", "/api/anchors")).body?.anchors ?? []).every((x) => x.witnesses.length === 0));
    execFileSync(process.execPath, ["--no-warnings", "scripts/admin.mjs", "witness-add", wkey, "Test", "Mirror"], { encoding: "utf8" });
    const w2 = run([BASE, "--dir", dw, "--witness"]);
    const shown = (await api("GET", "/api/anchors")).body?.anchors ?? [];
    check("once accepted, its signature is recorded and shown with its name", /witnessed \d+ anchor/.test(w2.out) && shown.length > 0 && shown.every((x) => x.witnesses.length === 1 && x.witnesses[0].name === "Test Mirror" && x.witnesses[0].key === wkey), w2.out + JSON.stringify(shown[0]));
    let vout = "";
    try { vout = execFileSync(process.execPath, ["--no-warnings", "scripts/verify-log.mjs", BASE], { encoding: "utf8" }); } catch (err) { vout = String(err.stdout || err); }
    check("the standalone verifier confirms the witness signatures", /carry valid signatures from 1 witness/.test(vout) && /The record is consistent/.test(vout), vout);
    const anchorId = shown[0].id, headText = await (await fetch(`${BASE}/api/anchors/${anchorId}/head`)).text();
    const wpost = (body) => rawPost(`/api/anchors/${anchorId}/witness`, JSON.stringify(body));
    const { generateKeyPairSync, sign: edSign, createHash: ch } = await import("node:crypto");
    const stranger = generateKeyPairSync("ed25519");
    const sKey = stranger.publicKey.export({ format: "jwk" }).x, sAt = Date.now();
    const sSig = edSign(null, Buffer.from(`zesuro:witness:v1:${ch("sha256").update(headText).digest("hex")}:${sAt}`), stranger.privateKey).toString("base64url");
    check("a signature from a key the operator hasn't accepted is refused", (await wpost({ key: sKey, at: sAt, sig: sSig })).status === 403);
    check("a forged signature under an accepted key is refused", (await wpost({ key: wkey, at: sAt, sig: sSig })).status === 400);
    execFileSync(process.execPath, ["--no-warnings", "scripts/admin.mjs", "witness-add", sKey, "Stranger"], { encoding: "utf8" });
    check("a witness can't claim to have seen an anchor before it existed", (await wpost({ key: sKey, at: shown[0].at - 3_600_000, sig: sSig })).status === 400 && (await wpost({ key: sKey, at: sAt, sig: sSig })).status === 201);
    // A witness refuses to sign for a record that was changed under it.
    await seal(k, { title: "After the witness copied", text: `later entry ${randomUUID()}` });
    execFileSync(process.execPath, ["--no-warnings", "scripts/anchor.mjs"], { encoding: "utf8" });
    mdb.prepare("UPDATE entries SET entry_hash = ? WHERE seq = ?").run("e".repeat(64), lastSeq);
    const w3 = run([BASE, "--dir", dw, "--witness"]);
    const newest = ((await api("GET", "/api/anchors")).body?.anchors ?? [])[0];
    check("a witness does not sign once the site's history no longer matches its copy", w3.code === 2 && /history-rewritten/.test(w3.out) && newest.witnesses.length === 0, w3.out);
    mdb.prepare("UPDATE entries SET entry_hash = ? WHERE seq = ?").run(oldHash, lastSeq);
    const w4 = run([BASE, "--dir", dw, "--witness"]);
    check("with the record intact again it signs the new anchor", w4.code === 0 && ((await api("GET", "/api/anchors")).body?.anchors ?? [])[0].witnesses.some((x) => x.key === wkey), w4.out);
    execFileSync(process.execPath, ["--no-warnings", "scripts/admin.mjs", "witness-remove", sKey], { encoding: "utf8" });
    check("a removed witness is no longer shown", ((await api("GET", "/api/anchors")).body?.anchors ?? []).every((x) => !x.witnesses.some((y) => y.key === sKey)));
    srv.kill();
    mdb.close();
  }
  // Chat timer: age the first message past the 1-day timer set above, then read.
  const { DatabaseSync } = await import("node:sqlite");
  const tdb = new DatabaseSync("data/whenisaid.db");
  tdb.exec("PRAGMA busy_timeout = 10000;");
  const stored = tdb.prepare("SELECT blob FROM chat_messages WHERE id = ?").get(sentMsg.body.id);
  check("the database holds only ciphertext", typeof stored?.blob === "string" && !stored.blob.includes("dawn"));
  tdb.prepare("UPDATE chat_messages SET created_at = created_at - 90000000 WHERE id = ?").run(sentMsg.body.id);
  const afterTimer = (await chatApi("GET", roomUrl, null, A)).body;
  check("the timer deletes old messages and keeps recent ones", afterTimer?.messages?.length === 1 && afterTimer.messages[0].id !== sentMsg.body.id, JSON.stringify(afterTimer?.messages?.map((m) => m.id)));
  check("deleted chat's messages are gone from the database", tdb.prepare("SELECT COUNT(*) AS n FROM chat_messages WHERE room_id = ?").get(mj1.j.roomId).n === 0);
  const tomb = tdb.prepare("SELECT invite_id, join_blob, created_at, slot, deleted_at FROM chat_rooms WHERE id = ?").get(mj1.j.roomId);
  check("a deleted chat keeps no link to its invite, its handshake or its start time", tomb && tomb.invite_id === "" && tomb.join_blob === "" && tomb.created_at === 0 && tomb.slot === null && tomb.deleted_at > 0, JSON.stringify(tomb));
  // The site altering an unrevealed entry's text can't make the author vouch for it.
  const tam = await seal(k, { title: "Tamper target", text: `original words ${randomUUID()}` });
  tdb.prepare("UPDATE entries SET text = ? WHERE uid = ?").run("words the author never wrote", tam.uid);
  const tamRes = await api("POST", `/api/entries/${tam.uid}/reveal`, await opening(k, tam.uid, tam.nonce, "Author"));
  check("an entry whose text was altered by the site can't be revealed as the author's", tamRes.status === 403, JSON.stringify(tamRes.body));
  tdb.prepare("UPDATE entries SET text = ? WHERE uid = ?").run(tam.res.body.entry.text, tam.uid);
  check("with the original text restored, the same opening works", (await api("POST", `/api/entries/${tam.uid}/reveal`, await opening(k, tam.uid, tam.nonce, "Author"))).status === 200);
  tdb.close();
} else console.log("SKIP  admin tool checks (not running beside the database)");
await new Promise((r) => setTimeout(r, 10_500)); // let the cached chain check refresh
const chain5 = (await api("GET", "/api/chain")).body;
check("both chains still verify after flags and admin actions", chain5?.ok === true && chain5?.comments?.ok === true, JSON.stringify(chain5));

console.log(failed ? `\n${failed} check(s) FAILED` : "\nAll checks passed");
process.exit(failed ? 1 : 0);

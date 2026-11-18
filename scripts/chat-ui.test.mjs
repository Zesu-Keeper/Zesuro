// Two-browser test of the private chat. Needs Playwright, which is not a project dependency:
//   npm i playwright && npx playwright install chromium-headless-shell   (anywhere), then
//   BASE_URL=http://127.0.0.1:3000 node scripts/chat-ui.test.mjs
import { chromium } from "playwright";
import { webcrypto, createHash, randomUUID } from "node:crypto";
const BASE = process.env.BASE_URL || "http://127.0.0.1:3100";
const { subtle } = webcrypto;
const hex = (b) => Buffer.from(b).toString("hex");
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
let failed = 0;
const check = (n, c, x = "") => { if (!c) failed++; console.log(`${c ? "PASS" : "FAIL"}  ${n}${c ? "" : "  " + x}`); };

// A device key and one sealed entry for the source, made the way the site makes them.
const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const priv = await subtle.exportKey("jwk", pair.privateKey);
const stored = { priv: { kty: "EC", crv: "P-256", x: priv.x, y: priv.y, d: priv.d, ext: true, key_ops: ["sign"] }, pub: { kty: "EC", crv: "P-256", x: priv.x, y: priv.y, ext: true, key_ops: ["verify"] } };
const canon = JSON.stringify({ crv: "P-256", kty: "EC", x: priv.x, y: priv.y });
const nonce = hex(webcrypto.getRandomValues(new Uint8Array(16)));
const hk = await subtle.importKey("raw", Buffer.from(priv.d, "base64url"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
const salt = hex(await subtle.sign("HMAC", hk, new TextEncoder().encode(nonce)));
const uid = randomUUID();
const TICKET = (await (await fetch(BASE + "/api/ticket")).json()).ticket;
await new Promise((r) => setTimeout(r, 2500)); // tickets must be a moment old
const title = "Browser test entry " + uid.slice(0, 8);
const text = `ui test ${uid}`;
const sealRes = await fetch(BASE + "/api/entries", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ uid, nonce, title, text, commitment: sha256(`${canon}:${salt}`), mode: "manual", ticket: TICKET }) });
check("entry sealed for the test", sealRes.status === 201, await sealRes.text());

const browser = await chromium.launch();
const errors = [];
const mk = async (name) => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  page.on("console", (m) => { if (m.type() === "error") errors.push(`${name}: ${m.text()}`); });
  page.on("pageerror", (e) => errors.push(`${name}: ${e.message}`));
  page.on("dialog", (d) => d.accept());
  return { ctx, page };
};
const A = await mk("source"), B = await mk("reporter"), X = await mk("third");
await A.page.goto(BASE + "/chat");
await A.page.evaluate(([k, m]) => { localStorage.setItem("whenisaid.key.v1", k); localStorage.setItem("whenisaid.mine.v1", m); }, [JSON.stringify(stored), JSON.stringify([{ uid, nonce, title, text, createdAt: Date.now(), mode: "manual" }])]);
await A.page.reload();
await A.page.getByRole("button", { name: "Make a chat link" }).click();
const linkBox = A.page.getByLabel("Chat link");
await linkBox.waitFor({ timeout: 20000 });
const link = await linkBox.inputValue();
check("link has its secret after the #", /\/chat#i=[A-Za-z0-9_-]{43}$/.test(link), link);
check("source sees their source ID", await A.page.getByText(/Your source ID is/).isVisible());

await A.page.goto(link); // the creator opening their own link must not use it up
await A.page.getByText("This is a link you made in this browser").waitFor({ timeout: 10000 });
check("creator opening own link does not use it", true);
await A.page.goto(BASE + "/chat");

await B.page.goto(link);
await B.page.getByRole("button", { name: "Open the chat" }).click();
await B.page.waitForURL(/#r=/, { timeout: 20000 });
check("reporter lands in the room, secret gone from the address bar", !B.page.url().includes("#i="));

await X.page.goto(link);
await X.page.getByText("This link has already been used").waitFor({ timeout: 10000 });
check("a third person is told the one-time link was used", true);

await A.page.getByRole("button", { name: "Open", exact: true }).click({ timeout: 20000 });
await A.page.getByText(/The other person sees you only as/).waitFor({ timeout: 20000 });
await B.page.getByText("Source verified").waitFor({ timeout: 20000 });
const idA = await A.page.locator(".chat-head .mono").first().innerText();
const idB = await B.page.locator(".chat-head .mono").first().innerText();
check("both sides show the same source ID", /^ZS-/.test(idA) && idA === idB, `${idA} ${idB}`);
const sA = await A.page.locator(".chat-head .mono").nth(1).innerText(), sB = await B.page.locator(".chat-head .mono").nth(1).innerText();
check("both sides show the same safety code", /^\d{4} \d{4} \d{4}$/.test(sA) && sA === sB, `${sA} ${sB}`);

await A.page.getByLabel("Message", { exact: true }).fill("Hello from the source\nsecond line");
await A.page.getByRole("button", { name: "Send" }).click();
await B.page.getByText("Hello from the source").waitFor({ timeout: 15000 });
await B.page.getByLabel("Message", { exact: true }).fill("Reply from the reporter <b>x</b>");
await B.page.getByRole("button", { name: "Send" }).click();
await A.page.getByText("Reply from the reporter <b>x</b>").waitFor({ timeout: 15000 });
check("messages travel both ways, as plain text", true);
check("own messages sit on the right", await A.page.locator(".chat-msg.me").count() === 1 && await A.page.locator(".chat-msg.them").count() === 1);

await A.page.getByLabel("Entry to prove").selectOption(uid);
await A.page.getByRole("button", { name: "Prove it" }).click();
await B.page.locator(".chat-proof.ok").waitFor({ timeout: 20000 });
check("reporter sees the post verified, with its title", (await B.page.locator(".chat-proof.ok").innerText()).includes(title));
await A.page.locator(".chat-proof.ok").waitFor({ timeout: 20000 });
check("reporter has no proof controls", await B.page.getByText("Prove a post is yours").count() === 0);

await B.page.getByLabel("Message timer").selectOption("604800000");
await A.page.getByText(/set the timer to "Delete after 7 days"/).waitFor({ timeout: 15000 });
check("timer change shows for the other side", await A.page.getByLabel("Message timer").inputValue() === "604800000");

await B.page.reload();
await B.page.getByText("Hello from the source").waitFor({ timeout: 15000 });
await B.page.getByText("Source verified").waitFor({ timeout: 15000 });
check("chat survives a reload", await B.page.locator(".err").count() === 0, await B.page.locator(".err").allInnerTexts().then((t) => t.join("|")));
check("no integrity warnings in a clean chat", await A.page.locator(".err").count() === 0);

await B.page.goto(link);
await B.page.waitForURL(/#r=/, { timeout: 10000 });
check("reporter reopening the used link returns to their chat", true);

// Move the chat to a fresh browser with the chat key.
const roomId = B.page.url().split("#r=")[1];
const access = await B.page.evaluate((id) => { const r = JSON.parse(localStorage.getItem("whenisaid.chats.v1")).rooms.find((x) => x.id === id); return "zesuro-chat:v1:" + btoa(JSON.stringify({ id: r.id, role: r.role, master: r.master, createdAt: r.createdAt })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }, roomId);
await X.page.goto(BASE + "/chat");
await X.page.getByText("Move a chat from another browser").click();
await X.page.getByLabel("Chat key").fill(access);
await X.page.getByRole("button", { name: "Add chat" }).click();
await X.page.getByText("Hello from the source").waitFor({ timeout: 15000 });
await X.page.getByLabel("Message", { exact: true }).fill("Sent from the second device");
await X.page.getByRole("button", { name: "Send" }).click();
await A.page.getByText("Sent from the second device").waitFor({ timeout: 15000 });
check("a moved chat continues without integrity warnings", await A.page.locator(".err").count() === 0, await A.page.locator(".err").allInnerTexts().then((t) => t.join("|")));

const Y = await mk("stranger");
await Y.page.goto(`${BASE}/chat#r=${roomId}`);
await Y.page.getByText("This browser doesn't hold the key to that chat").waitFor({ timeout: 10000 });
check("a stranger with only the room address gets nothing", true);

await A.page.getByRole("button", { name: "Delete chat" }).click();
await A.page.getByText("Your chats").waitFor({ timeout: 10000 });
await B.page.getByText("This chat was deleted").waitFor({ timeout: 20000 });
check("deleting removes the chat for both", true);

const real = errors.filter((e) => !/status of 410/.test(e)); // 410 is the expected "chat deleted" answer
check("no browser console errors", real.length === 0, real.slice(0, 5).join(" || "));
await browser.close();
console.log(failed ? `\n${failed} check(s) failed` : "\nAll checks passed");
process.exit(failed ? 1 : 0);

// Browser test of sealing, revealing and restoring through the real pages. Needs Playwright (not a project dependency):
//   BASE_URL=http://127.0.0.1:3000 node --import ./scripts/ts-resolve.mjs scripts/say-ui.test.mjs
import { chromium } from "playwright";
import * as K from "../src/lib/client-crypto.ts";
const BASE = process.env.BASE_URL || "http://127.0.0.1:3100";
let failed = 0;
const check = (n, c, x = "") => { if (!c) failed++; console.log(`${c ? "PASS" : "FAIL"}  ${n}${c ? "" : "  " + x}`); };
const browser = await chromium.launch();
const errors = [];
const mk = async (perms = []) => {
  const ctx = await browser.newContext({ permissions: perms });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => { if (m.type() === "error" && !/status of (4\d\d)/.test(m.text())) errors.push(m.text()); });
  page.on("dialog", (d) => d.accept());
  return { ctx, page };
};
const A = await mk(["clipboard-read", "clipboard-write"]);
const p = A.page;
await p.goto(BASE + "/say");
const title = "Browser sealed " + Date.now();
await p.getByLabel("Title").fill(title);
await p.getByLabel("What do you want to say?").fill("The result will be [[Mr Green]] on the day, mark my words");
await p.getByRole("button", { name: "Seal", exact: true }).click();
await p.getByRole("dialog").waitFor();
// Manual mode is the default: seal it, which first asks for a key backup.
await p.getByRole("dialog").locator("button.primary").click();
await p.getByRole("button", { name: "Copy as text" }).click();
await p.getByLabel("I have saved my key somewhere safe").check();
await p.getByRole("button", { name: "Save key & seal" }).click();
await p.getByText(/Sealed ✓/).waitFor({ timeout: 30000 });
check("an entry is sealed from the real page", true);
const mine = await p.evaluate(() => JSON.parse(localStorage.getItem("whenisaid.mine.v1")));
const stored = await p.evaluate(() => JSON.parse(localStorage.getItem("whenisaid.key.v1")));
check("the browser records it as a version 2 entry", mine.length === 1 && mine[0].commitV === 2, JSON.stringify(mine[0]).slice(0, 120));
const uid = mine[0].uid;
const entry = (await (await fetch(`${BASE}/api/entries/${uid}`)).json()).entry;
check("the record says version 2, with the redaction", entry.commitV === 2 && entry.redactions === 1 && entry.text.includes("mark my words"));
check("the device key owns exactly this entry", await K.ownsEntry(stored, entry));
check("an altered copy of it would not be owned", !(await K.ownsEntry(stored, { ...entry, text: entry.text + "!" })));
check("the device key's public key is not in the entry's public data", !JSON.stringify(entry).includes(stored.pub.x));

// Reveal from Mine
await p.goto(BASE + "/mine");
await p.getByRole("button", { name: /Reveal/ }).first().click();
await p.getByLabel("Name to show on this entry").fill("Alex R.");
await p.getByRole("button", { name: "Reveal now" }).click();
await p.getByText("Alex R.").first().waitFor({ timeout: 20000 });
const rev = (await (await fetch(`${BASE}/api/entries/${uid}`)).json()).entry;
check("the reveal is accepted for a version 2 entry", rev.status === "revealed" && rev.handle === "Alex R." && rev.opening?.v === 2 && rev.opening.pub.kty === "OKP", JSON.stringify(rev.opening)?.slice(0, 100));
check("the revealed key is not the device key", rev.opening.pub.x !== stored.pub.x);
check("the redacted words were released with the reveal", rev.parts?.[0] === "Mr Green");
await p.goto(`${BASE}/e/${uid}`);
await p.getByText("Check the author's claim").click();
check("the entry page explains the version 2 check", await p.getByText(/zesuro:commit:v2/).first().isVisible());
check("the entry page recognises its author", await p.getByText("You sealed this entry").isVisible());

// Restore the key on another device
const key = K.exportKeyString(stored);
const B = await mk();
await B.page.goto(BASE + "/mine");
await B.page.getByText("Restore a key on this device").click();
await B.page.getByRole("textbox").last().fill(key);
await B.page.getByRole("button", { name: "Restore" }).click();
await B.page.getByText(/Found 1 of your entry|Found 1 of your entries/).waitFor({ timeout: 30000 });
check("restoring the key finds the entry by its content-bound commitment", true);
await B.page.goto(`${BASE}/e/${uid}`);
let recognised = true;
try { await B.page.getByText("You sealed this entry").waitFor({ timeout: 15000 }); } catch { recognised = false; }
check("and the second device is recognised as the author", recognised);
// A third browser with no key is not.
const C = await mk();
await C.page.goto(`${BASE}/e/${uid}`);
await C.page.waitForTimeout(3000);
check("a browser without the key is not shown as the author", !(await C.page.getByText("You sealed this entry").isVisible()));

check("no browser errors", errors.length === 0, errors.slice(0, 4).join(" || "));
await browser.close();
console.log(failed ? `\n${failed} check(s) failed` : "\nAll checks passed");
process.exit(failed ? 1 : 0);

// Tests for the private chat addresses helpers: lib/chat-hosts.ts.
// Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/chat-hosts.test.mjs
import assert from "node:assert/strict";
const H = await import(new URL("../src/lib/chat-hosts.ts", import.meta.url).pathname);
let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };

const apexes = H.parseChatApexes(" Chat-One.example , chat-two.example,not a host, , localhost,x.y");
ok(apexes.join() === "chat-one.example,chat-two.example", "domains are lower-cased and bad entries dropped");
ok(H.parseChatApexes(undefined).length === 0 && H.parseChatApexes("").length === 0, "nothing configured means nothing is served");

ok(H.hostKind("zesuro.com", apexes) === "main" && H.hostKind(null, apexes) === "main" && H.hostKind("", apexes) === "main", "the main site is the main site");
ok(H.hostKind("chat-one.example", apexes) === "apex" && H.hostKind("CHAT-TWO.example:443", apexes) === "apex", "the bare chat domain is recognised, with a port or capitals");
ok(H.hostKind("k3x9abc.chat-one.example", apexes) === "chat", "a random address is a chat address");
ok(H.hostKind("a.b.chat-one.example", apexes) === "main", "a deeper name is not a chat address");
ok(H.hostKind("evilchat-one.example", apexes) === "main" && H.hostKind("chat-one.example.evil.com", apexes) === "main", "look-alike names are not chat addresses");
ok(H.hostKind("x.chat-one.example", []) === "main", "with no domains configured every name is the main site");

const seen = new Set();
for (let i = 0; i < 500; i++) {
  const l = H.randomLabel();
  ok(/^[a-z0-9]{24}$/.test(l), "a label is 24 lower-case letters and digits");
  seen.add(l);
}
ok(seen.size === 500, "labels are never repeated");
const o = H.randomChatOrigin(apexes);
ok(/^https:\/\/[a-z0-9]{24}\.(chat-one|chat-two)\.example$/.test(o), "a chat origin is a random label under one of the domains");
ok(H.randomChatOrigin([]) === null, "no domains, no origin");
const doms = new Set();
for (let i = 0; i < 100; i++) doms.add(H.randomChatOrigin(apexes).split(".").slice(1).join("."));
ok(doms.size === 2, "both domains get used");
ok(H.hostKind(new URL(o).host, apexes) === "chat", "a made origin is recognised as a chat address");

console.log(`All ${n} chat hosts checks passed.`);

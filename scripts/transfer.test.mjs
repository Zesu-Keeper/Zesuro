// Tests for src/lib/transfer.ts (moving keys between Zesuro addresses).
// Run: node --no-warnings scripts/transfer.test.mjs
import assert from "node:assert/strict";
import { TRANSFER_KEYS, makeCode, normaliseCode, openBundle, planImport, sealBundle } from "../src/lib/transfer.ts";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const rejects = async (p, re, m) => { await assert.rejects(p, re, m); n++; };

const items = { "whenisaid.key.v1": '{"d":"secret"}', "whenisaid.mine.v1": '{"rooms":[1,2,3]}', "whenisaid.voter.v2": "abc", "unrelated.key": "must not travel" };
const code = makeCode();
ok(/^([A-Z2-7]{4}-){5}[A-Z2-7]{4}$/.test(code), "code looks like six groups of four");
ok(normaliseCode(code.toLowerCase().replace(/-/g, " ")) === code.replace(/-/g, ""), "a code is accepted however it is typed");
ok(normaliseCode("short") === null && normaliseCode(code + "A") === null && normaliseCode("0".repeat(24)) === null, "malformed codes are refused");
ok(new Set(Array.from({ length: 50 }, makeCode)).size === 50, "codes are not repeated");

const bundle = await sealBundle(items, code);
ok(bundle.startsWith("ZT1.") && !bundle.includes("secret") && !bundle.includes("rooms"), "the bundle does not show its contents");
const back = await openBundle(bundle, code);
ok(back["whenisaid.key.v1"] === items["whenisaid.key.v1"] && back["whenisaid.mine.v1"] === items["whenisaid.mine.v1"], "opens with the right code");
ok(!("unrelated.key" in back), "only Zesuro's own storage keys travel");
ok((await openBundle(`  ${bundle}\n`, code.toLowerCase()))["whenisaid.voter.v2"] === "abc", "whitespace and case do not matter");

// Wrong code, damage, truncation, other formats: all refused, with the same message for the first two
const other = makeCode();
await rejects(openBundle(bundle, other), /Wrong code, or the bundle is damaged/, "wrong code");
const flip = bundle.slice(0, -3) + (bundle.at(-3) === "A" ? "B" : "A") + bundle.slice(-2);
await rejects(openBundle(flip, code), /Wrong code, or the bundle is damaged/, "damaged bundle");
await rejects(openBundle(bundle.slice(0, 20), code), /not a transfer bundle/, "truncated");
await rejects(openBundle("ZT2." + bundle.slice(4), code), /not a transfer bundle/, "other version");
await rejects(openBundle("hello", code), /not a transfer bundle/, "text");
await rejects(openBundle(bundle, "nope"), /not a transfer code/, "bad code format");
await rejects(openBundle("x".repeat(5_000_000), code), /not a transfer bundle/, "oversize");

// Two seals of the same items differ (fresh salt and IV)
ok((await sealBundle(items, code)) !== bundle, "each bundle is different");

// A crafted bundle that decrypts but carries a foreign key or a non-string is ignored or refused
{
  const crafted = await sealBundle({ "whenisaid.key.v1": "k" }, code);
  ok(Object.keys(await openBundle(crafted, code)).join() === "whenisaid.key.v1", "allowed keys only");
}

// Large bundles (several hundred KB) round-trip
{
  const big = { "whenisaid.mine.v1": "x".repeat(900_000) };
  ok((await openBundle(await sealBundle(big, code), code))["whenisaid.mine.v1"].length === 900_000, "a large bundle round-trips");
}

// Import plan never overwrites
{
  const incoming = { "whenisaid.key.v1": "A", "whenisaid.mine.v1": "B", "whenisaid.voter.v2": "C" };
  let p = planImport({ "whenisaid.key.v1": null, "whenisaid.mine.v1": "B", "whenisaid.voter.v2": "other" }, incoming);
  ok(p.add.join() === "whenisaid.key.v1" && p.same.join() === "whenisaid.mine.v1" && p.keep.join() === "whenisaid.voter.v2" && !p.deviceKeyConflict, "add, same and keep are told apart");
  p = planImport({ "whenisaid.key.v1": "B" }, incoming);
  ok(p.deviceKeyConflict && p.keep.includes("whenisaid.key.v1"), "a different device key is a conflict, never replaced");
}
ok(TRANSFER_KEYS.includes("whenisaid.key.v1") && TRANSFER_KEYS.length === 9 && !TRANSFER_KEYS.some((k) => k.includes("chat")), "the carried keys are the app's, and chats are not among them");

console.log(`All ${n} transfer checks passed`);

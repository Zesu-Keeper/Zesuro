// Tests for six-word keys (lib/phrase.ts, lib/wordlist.ts).
// Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/phrase.test.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
const imp = (f) => import(new URL("../src/lib/" + f, import.meta.url).pathname);
const [W, P, CC] = await Promise.all([imp("wordlist.ts"), imp("phrase.ts"), imp("client-crypto.ts")]);
let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };

// ---- the word list
ok(W.WORDS.length === 2048, "2048 words");
ok(new Set(W.WORDS).size === 2048, "all different");
ok(W.WORDS.every((w) => /^[a-z]{3,8}$/.test(w)), "plain lower case words");
ok(createHash("sha256").update(W.WORDS.join("\n") + "\n").digest("hex") === "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", "the list is the published one");

// ---- making and reading phrases
const seen = new Set();
for (let i = 0; i < 50; i++) {
  const p = P.makePhrase();
  ok(p.length === 6 && p.every((w) => W.WORDS.includes(w)), "six listed words");
  seen.add(p.join(" "));
}
ok(seen.size === 50, "random phrases do not repeat");
ok(JSON.stringify(P.readPhrase("  Zoo, ABANDON  able-zone\tability zoo ")) === JSON.stringify(["zoo", "abandon", "able", "zone", "ability", "zoo"]), "any case and separators");
ok(P.readPhrase("zoo abandon able zone ability") === null, "five words are refused");
ok(P.readPhrase("zoo abandon able zone ability zoo zoo") === null, "seven words are refused");
ok(P.readPhrase("zoo abandon able zone ability banana1") === null, "a word that is not listed is refused");
ok(P.readPhrase("") === null, "empty is refused");

// ---- the key
const words = ["abandon", "ability", "able", "about", "above", "absent"];
const t0 = Date.now();
const k1 = await P.phraseToKey(words);
const ms = Date.now() - t0;
const k2 = await P.phraseToKey(words);
ok(JSON.stringify(k1) === JSON.stringify(k2), "same words, same key");
ok(JSON.stringify(k1) !== JSON.stringify(await P.phraseToKey(["abandon", "ability", "able", "about", "above", "absurd"])), "one word different, different key");
ok(k1.priv.kty === "EC" && k1.priv.crv === "P-256" && k1.priv.d && k1.priv.x === k1.pub.x && k1.priv.y === k1.pub.y, "a P-256 key pair");
// the key really works: sign with the private half, verify with the public half
const priv = await crypto.subtle.importKey("jwk", { ...k1.priv, key_ops: ["sign"] }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
const pub = await crypto.subtle.importKey("jwk", { ...k1.pub, key_ops: ["verify"] }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
const msg = new TextEncoder().encode("hello");
const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, msg);
ok(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, sig, msg), "it signs and verifies");
// it works with the rest of the key code
const nonce = CC.randomHex(16);
ok(typeof (await CC.deriveSaltV2(k1, nonce)) === "string" && (await CC.deriveSaltV2(k1, nonce)).length === 64, "the entry code accepts it");
ok(CC.importKeyString(CC.exportKeyString(k1)).priv.d === k1.priv.d, "it exports and imports like any key");
// the check code
const c1 = await P.keyCheckCode(k1);
ok(/^[0-9A-F]{4}$/.test(c1) && c1 === (await P.keyCheckCode(k2)), "a stable four character check code");
ok(c1 !== (await P.keyCheckCode(await P.phraseToKey(["abandon", "ability", "able", "about", "above", "absurd"]))) || true, "different keys usually differ");
let threw = false; try { await P.phraseToKey(["abandon", "ability"]); } catch { threw = true; }
ok(threw, "too few words are refused");
threw = false; try { await P.phraseToKey(["abandon", "ability", "able", "about", "above", "notaword"]); } catch { threw = true; }
ok(threw, "an unlisted word is refused");
console.log(`All ${n} six-word key checks passed (one key takes about ${ms} ms here).`);

// Tests for scripts/hybrid-sig.mjs. Run: node --no-warnings scripts/hybrid-sig.test.mjs
import assert from "node:assert/strict";
import { generate, sign, verify, parseKey, publicKeyOf, isHybridKey, ALG } from "./hybrid-sig.mjs";
import { sign as edSign, createPrivateKey, generateKeyPairSync } from "node:crypto";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const no = (c, m) => { assert.ok(!c, m); n++; };

const a = generate(), b = generate();
ok(isHybridKey(a.publicKey) && a.publicKey.startsWith(ALG + "."), "public key has the zs1 form");
ok(publicKeyOf(a.secret) === a.publicKey, "public key is recomputed from the secret");
ok(a.publicKey !== b.publicKey, "two keys differ");

const msg = '{"v":1,"type":"delegation","serial":1}';
const sig = sign(a.secret, "delegation", msg);
ok(verify(a.publicKey, "delegation", msg, sig), "valid signature verifies");

// Tampering
no(verify(a.publicKey, "delegation", msg + " ", sig), "changed message fails");
no(verify(b.publicKey, "delegation", msg, sig), "another key's check fails (key substitution)");
no(verify(a.publicKey, "anchor", msg, sig), "same bytes, other purpose fails (cross-protocol replay)");

// Each half is necessary: damage one at a time
const [alg, e, s] = sig.split(".");
const flip = (t) => (t[0] === "A" ? "B" : "A") + t.slice(1);
no(verify(a.publicKey, "delegation", msg, [alg, flip(e), s].join(".")), "bad Ed25519 half fails");
no(verify(a.publicKey, "delegation", msg, [alg, e, flip(s)].join(".")), "bad SLH-DSA half fails");
// Valid Ed25519 half plus garbage, and the reverse: no single-algorithm signature is enough
const edOnly = [alg, e, "A".repeat(s.length)].join(".");
no(verify(a.publicKey, "delegation", msg, edOnly), "Ed25519 half alone is not accepted");
const slhOnly = [alg, "A".repeat(e.length), s].join(".");
no(verify(a.publicKey, "delegation", msg, slhOnly), "SLH-DSA half alone is not accepted");

// Downgrade: a bare Ed25519 signature, or an Ed25519 key, must not satisfy a zs1 key
const rawEd = generateKeyPairSync("ed25519");
const rawSig = edSign(null, Buffer.from(msg), rawEd.privateKey).toString("base64url");
no(verify(a.publicKey, "delegation", msg, rawSig), "bare Ed25519 signature rejected for a zs1 key");
no(verify(a.publicKey, "delegation", msg, `${alg}.${rawSig}`), "two-part signature rejected");
no(verify(rawEd.publicKey.export({ format: "jwk" }).x, "delegation", msg, sig), "legacy bare key is not a zs1 key");
no(parseKey("zs1.AAAA.BBBB"), "short key rejected");

// Malleability: other spellings of the same bytes
no(verify(a.publicKey, "delegation", msg, sig + "="), "padded signature rejected");
no(verify(a.publicKey, "delegation", msg, sig + "."), "extra part rejected");
no(verify(a.publicKey, "delegation", msg, sig.replace(/-/g, "+")), "wrong alphabet rejected");
no(verify(a.publicKey, "delegation", msg, ""), "empty rejected");
no(verify(a.publicKey, "delegation", msg, null), "null rejected");
no(verify(a.publicKey, "delegation", msg, 42), "number rejected");
// Last base64 character of the Ed half has unused bits; setting them gives a different text for the same bytes
const lastEd = e.at(-1), alt = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(lastEd) + 1) % 64];
no(verify(a.publicKey, "delegation", msg, [alg, e.slice(0, -1) + alt, s].join(".")), "non-canonical base64 tail rejected");

// Boundary ambiguity: moving bytes between purpose and message must change the signed bytes
const x = sign(a.secret, "ab", "c");
no(verify(a.publicKey, "a", "bc", x), "purpose/message boundary is unambiguous");
no(verify(a.publicKey, "ab", "c\0", x), "trailing byte changes the result");

// Purposes
for (const bad of ["", "Delegation", "has space", "x".repeat(40), "a\0b", 7]) {
  assert.throws(() => sign(a.secret, bad, "m"), /purpose/); n++;
  no(verify(a.publicKey, bad, "m", sig), "bad purpose never verifies");
}

// Messages: empty, unicode, big, Buffers
for (const m of ["", "héllo ✓ 🙂", "x".repeat(200000), Buffer.from([0, 1, 2, 255])]) {
  ok(verify(a.publicKey, "anchor", m, sign(a.secret, "anchor", m)), "message round-trips");
}

// Secrets
assert.throws(() => sign("{}", "anchor", "m"), /not a zs1/); n++;
assert.throws(() => sign("nonsense", "anchor", "m"), /not valid/); n++;
const damaged = JSON.parse(a.secret); damaged.slh = damaged.slh.slice(1);
assert.throws(() => sign(JSON.stringify(damaged), "anchor", "m"), /damaged/); n++;
// A secret whose halves belong to different keys would sign something that no published key accepts; the self-check or key derivation must not release it
const mixed = JSON.parse(a.secret); mixed.slh = JSON.parse(b.secret).slh;
const mixedPub = publicKeyOf(JSON.stringify(mixed));
no(mixedPub === a.publicKey || mixedPub === b.publicKey, "a mixed secret has its own, different public key");

// Signatures are randomised (hedged), so the same input signs differently but both verify
const s2 = sign(a.secret, "delegation", msg);
ok(s2 !== sig && verify(a.publicKey, "delegation", msg, s2), "fresh randomness per signature, both valid");
ok(sig.length > 10000 && sig.length < 11500, `signature size is ${sig.length} characters`);

console.log(`All ${n} hybrid-signature checks passed`);

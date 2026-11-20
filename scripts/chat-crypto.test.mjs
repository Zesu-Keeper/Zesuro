// Tests the chat crypto on its own (no server). Usage: node scripts/chat-crypto.test.mjs
import { webcrypto, createHash } from "node:crypto";
import * as C from "../src/lib/chat-crypto.ts";
import * as K from "../src/lib/client-crypto.ts";

let failed = 0;
const check = (name, cond, extra = "") => {
  if (!cond) failed++;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond ? "" : "  " + extra}`);
};
const { subtle } = webcrypto;

const inv = await C.newInvite(3);
check("link secret is 43 url-safe characters", /^[A-Za-z0-9_-]{43}$/.test(inv.secret));
check("fragment round-trips", C.parseInviteFragment("#" + C.inviteFragment(inv.secret)) === inv.secret);
check("junk fragments are rejected", C.parseInviteFragment("#i=abc") === null && C.parseInviteFragment("#r=" + inv.secret) === null);
check("invite id is a hash, not the secret", inv.id === await C.inviteIdOf(inv.secret) && !inv.id.includes(inv.secret) && /^[0-9a-f]{64}$/.test(inv.id));
check("one creator key per allowed use", inv.privs.length === 3 && new Set(inv.privs.map((p) => p.x)).size === 3);
check("hello does not expose any public key", inv.privs.every((p) => !inv.hello.includes(p.x)));
check("'as many as allowed' makes one key each for 100 uses", (await C.newInvite(0)).privs.length === C.MAX_USES);
check("a link for 1 use has 1 key", (await C.newInvite(1)).privs.length === 1);

const j = await C.joinWith(inv.secret, inv.hello, 1);
const mA = (await C.acceptJoin(inv.secret, inv.privs[1], j.roomId, j.join, 1))?.master;
check("both sides derive the same master key", mA === j.master && mA.length === 43);
const kA = await C.roomKeys(mA, j.roomId), kB = await C.roomKeys(j.master, j.roomId);
check("same token, binding and safety code", kA.token === kB.token && kA.bind === kB.bind && kA.safety === kB.safety);
check("safety code is 24 characters (120 bits) in six groups", /^([0-9A-HJKMNP-TV-Z]{4} ){5}[0-9A-HJKMNP-TV-Z]{4}$/.test(kA.safety), kA.safety);
check("auth hash is the hash of the token", j.authHash === createHash("sha256").update(kB.token).digest("hex"));
check("the wrong creator key can't accept a join", await C.acceptJoin(inv.secret, inv.privs[0], j.roomId, j.join, 1) === null && await C.acceptJoin(inv.secret, inv.privs[2], j.roomId, j.join, 1) === null);
check("an erased creator key can't accept (that chat is no longer re-derivable)", await C.acceptJoin(inv.secret, null, j.roomId, j.join, 1) === null);
check("a join can't be moved to another slot", await C.acceptJoin(inv.secret, inv.privs[0], j.roomId, j.join, 0) === null);
let threw = false;
try { await C.joinWith(inv.secret, inv.hello, 3); } catch { threw = true; }
check("a slot beyond the link's uses is refused", threw);

const j2 = await C.joinWith(inv.secret, inv.hello, 2);
const mA2 = (await C.acceptJoin(inv.secret, inv.privs[2], j2.roomId, j2.join, 2))?.master;
check("a second opener gets a different key", mA2 === j2.master && mA2 !== mA);
check("join blob can't be moved to another room", await C.acceptJoin(inv.secret, inv.privs[2], j.roomId, j2.join, 2) === null);

const other = await C.newInvite(1);
threw = false;
try { await C.joinWith(inv.secret, other.hello, 0); } catch { threw = true; }
check("a hello swapped by the server is refused", threw);
check("a join made without the link secret is refused", await C.acceptJoin(inv.secret, inv.privs[1], j.roomId, (await C.joinWith(other.secret, other.hello, 0)).join, 1) === null);
const mitm = await C.newInvite(3);
check("another key pair can't accept the join", await C.acceptJoin(inv.secret, mitm.privs[1], j.roomId, j.join, 1) === null);

const blob = await C.encryptMessage(kA, j.roomId, "a", 0, { kind: "text", text: "héllo ✓" });
const got = await C.decryptMessage(kB, j.roomId, blob);
check("message round-trips", got?.kind === "text" && got.text === "héllo ✓" && got.from === "a" && got.n === 0);
const sizes = new Set();
for (const len of [1, 50, 500, 900]) sizes.add((await C.encryptMessage(kA, j.roomId, "a", 1, { kind: "text", text: "x".repeat(len) })).length);
check("short messages all have the same size", sizes.size === 1, [...sizes].join(","));
check("longest message fits", (await C.encryptMessage(kA, j.roomId, "b", 2, { kind: "text", text: "\u{1F600}".repeat(C.MAX_TEXT / 2) })).length < 46000);
const bad = blob.slice(0, 40) + (blob[40] === "A" ? "B" : "A") + blob.slice(41);
check("altered message is rejected", await C.decryptMessage(kB, j.roomId, bad) === null);
check("message from another room is rejected", await C.decryptMessage(await C.roomKeys(j2.master, j2.roomId), j2.roomId, blob) === null);
check("message replayed into another room id is rejected", await C.decryptMessage(kB, j2.roomId, blob) === null);
const forged = await C.encryptMessage({ ...kA, b2a: kA.a2b }, j.roomId, "b", 0, { kind: "text", text: "x" });
check("sender can't be mislabelled", await C.decryptMessage(kB, j.roomId, forged) === null);
// The other person holds a key too, so what they send must be well-formed.
const junk = async (body, n = 0) => C.decryptMessage(kA, j.roomId, await C.encryptMessage(kB, j.roomId, "b", n, body));
check("text that isn't a string is rejected", await junk({ kind: "text", text: { a: 1 } }) === null && await junk({ kind: "text", text: "" }) === null);
check("an unknown kind is rejected", await junk({ kind: "script", text: "x" }) === null);
check("a malformed proof or introduction is rejected", await junk({ kind: "proof", uid: "nope", pub: "x", salt: "y", sig: "z" }) === null && await junk({ kind: "id", pub: "short", sig: "s" }) === null);
check("a timer value that isn't offered is rejected", await junk({ kind: "timer", ttl: 5 }) === null && (await junk({ kind: "timer", ttl: 86_400_000 }))?.ttl === 86_400_000);
check("a huge message number is rejected", await junk({ kind: "text", text: "x" }, 9_007_199_254_740_991) === null);

// The source's identity in a chat, and proofs of entries
const dev = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const priv = await subtle.exportKey("jwk", dev.privateKey);
const stored = { priv: { kty: "EC", crv: "P-256", x: priv.x, y: priv.y, d: priv.d }, pub: { kty: "EC", crv: "P-256", x: priv.x, y: priv.y } };
const secretBytes = K.b64uToBytes(priv.d);
const idA = await C.chatIdentity(secretBytes, j.roomId), idA2 = await C.chatIdentity(secretBytes, j.roomId), idB = await C.chatIdentity(secretBytes, j2.roomId);
check("a chat identity is stable within a chat and differs between chats", idA.pubX === idA2.pubX && idA.pubX !== idB.pubX);
const ps = await C.pseudonymOf(idA.pubX);
check("pseudonym has the expected shape and differs between chats", /^ZS-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(ps) && ps !== await C.pseudonymOf(idB.pubX), ps);
check("the pseudonym can't be computed from the device's public key", ps !== await C.pseudonymOf(priv.x) );
const sig = await C.signIdentity(idA.sign, j.roomId, kA.bind);
check("identity signature verifies in its own chat", await C.verifyIdentity(idA.pubX, sig, j.roomId, kB.bind));
const k2 = await C.roomKeys(j2.master, j2.roomId);
check("identity signature can't be replayed into another chat", !(await C.verifyIdentity(idA.pubX, sig, j2.roomId, k2.bind)) && !(await C.verifyIdentity(idA.pubX, sig, j.roomId, k2.bind)));

// Entry proofs, with the same code the browser uses to seal entries
const nonce = "ab".repeat(16);
const content = { uid: "11111111-1111-4111-8111-111111111111", title: "A title", text: "Some text", placeMode: "none", place: null, secretCommit: null, mode: "manual" };
const commitment = await K.commitmentV2(stored, nonce, content);
const ek = await K.entryKey(stored, nonce), salt = await K.deriveSaltV2(stored, nonce);
check("proof opens the entry's commitment", await C.proofMatches(ek.pubX, salt, content, commitment));
check("the same text under another entry id does not match", !(await C.proofMatches(ek.pubX, salt, { ...content, uid: "22222222-2222-4222-8222-222222222222" }, commitment)));
check("altered text does not match", !(await C.proofMatches(ek.pubX, salt, { ...content, text: "Other text" }, commitment)) && !(await C.proofMatches(ek.pubX, salt, { ...content, title: "Other" }, commitment)));
check("another key or salt does not match", !(await C.proofMatches(idA.pubX, salt, content, commitment)) && !(await C.proofMatches(ek.pubX, "0".repeat(64), content, commitment)));
check("an author owns exactly the entries they sealed", await K.ownsEntry(stored, { ...content, nonce, commitment, commitV: 2 }) && !(await K.ownsEntry(stored, { ...content, text: "Changed", nonce, commitment, commitV: 2 })));
const psig = await C.signProof(ek.sign, j.roomId, kA.bind, content.uid);
check("proof signature verifies in its own chat for its own entry", await C.verifyProofSig(ek.pubX, psig, j.roomId, kB.bind, content.uid));
check("proof signature can't be reused in another chat or for another entry", !(await C.verifyProofSig(ek.pubX, psig, j2.roomId, k2.bind, content.uid)) && !(await C.verifyProofSig(ek.pubX, psig, j.roomId, kB.bind, "22222222-2222-4222-8222-222222222222")));
const ek2 = await K.entryKey(stored, "cd".repeat(16));
check("two entries from one device have unrelated public keys", ek.pubX !== ek2.pubX && ek.pubX !== priv.x && ek.pubX !== idA.pubX);

console.log(failed ? `\n${failed} check(s) failed` : "\nAll checks passed");
process.exit(failed ? 1 : 0);

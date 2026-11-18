// Tests for src/lib/timelock.ts (time-lock encryption to the drand quicknet beacon).
// Run: node --no-warnings scripts/timelock.test.mjs
// No network: the beacons below are real, past quicknet rounds copied from api.drand.sh. They
// verify against the pinned public key, which is the check that they are genuine.
import assert from "node:assert/strict";
import fs from "node:fs";
import { QUICKNET, MAX_PLAINTEXT, lockedRound, roundForTime, timeOfRound, timelockDecrypt, timelockEncrypt, verifyBeacon } from "../src/lib/timelock.ts";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const throwsWith = (fn, re, m) => { assert.throws(fn, re, m); n++; };
const T = new TextEncoder(), D = new TextDecoder();

const SIG = {
  1000000: "83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72",
  1000001: "a5bd91e5e2d8c0bf51bffdfad87eef34348fd9c0b2df2bee39db90bdef7e1399b1a77bb2fe98b24d84c0936a306c4218",
  2000000: "a7c94d62fa50475c65f259bc4d50afc0cebc5cb29848568f90dff842789c05d7f6b2414971a0b67bf532624ad6bab054",
};

// --- the beacon's clock
ok(timeOfRound(1) === QUICKNET.genesisSeconds * 1000, "round 1 is at genesis");
ok(timeOfRound(1000000) === (1692803367 + 999999 * 3) * 1000, "round time");
for (const r of [1, 2, 1000000, 34000000]) ok(roundForTime(timeOfRound(r)) === r, `a time exactly at round ${r} maps to it`);
ok(roundForTime(timeOfRound(1000000) + 1) === 1000001, "a moment after a round waits for the next");
ok(roundForTime(0) === 1, "times before genesis clamp to round 1");
ok(Math.abs(timeOfRound(roundForTime(Date.now())) - Date.now()) < 3000 + 1, "the round for now is within one period");

// --- beacon verification (real signatures against the pinned key)
ok(verifyBeacon(1000000, SIG[1000000]) && verifyBeacon(1000001, SIG[1000001]) && verifyBeacon(2000000, SIG[2000000]), "real beacons verify");
ok(!verifyBeacon(1000001, SIG[1000000]), "a signature for another round does not verify");
const flipHex = (h, i) => h.slice(0, i) + (h[i] === "0" ? "1" : "0") + h.slice(i + 1);
ok(!verifyBeacon(1000000, flipHex(SIG[1000000], 20)), "a damaged signature does not verify (and does not throw)");
ok(!verifyBeacon(1000000, "zz") && !verifyBeacon(1000000, "") && !verifyBeacon(0, SIG[1000000]) && !verifyBeacon(1.5, SIG[1000000]) && !verifyBeacon(1000000, SIG[1000000] + "00"), "garbage does not verify");

// --- interop: a file made by the reference implementation (tlock-js) opens here
const fx = JSON.parse(fs.readFileSync(new URL("./fixtures/timelock-tlockjs.json", import.meta.url), "utf8"));
ok(D.decode(timelockDecrypt(fx.theirs, SIG[1000000])) === fx.msg, "opens a file made by the reference implementation");
ok(lockedRound(fx.theirs) === 1000000, "reads the round from the header");

// --- round trips
const t0 = Date.now();
const secret = "The thing I said, in full. ✓ é \u{1F512}";
const armored = timelockEncrypt(T.encode(secret), 1000000);
const encMs = Date.now() - t0;
ok(armored.startsWith("-----BEGIN AGE ENCRYPTED FILE-----\n") && armored.endsWith("-----END AGE ENCRYPTED FILE-----\n"), "armored like any age file");
ok(!armored.includes(secret) && lockedRound(armored) === 1000000, "the text is not visible; the round is");
ok(D.decode(timelockDecrypt(armored, SIG[1000000])) === secret, "round trip with the real beacon");
ok(timelockEncrypt(T.encode(secret), 1000000) !== armored, "encrypting twice gives different files");
console.log(`(one encryption took ${encMs} ms)`);

// --- it cannot be opened without the right round's signature
throwsWith(() => timelockDecrypt(armored, SIG[1000001]), /does not open/, "another round's signature");
throwsWith(() => timelockDecrypt(armored, flipHex(SIG[1000000], 20)), /./, "a damaged signature");
throwsWith(() => timelockDecrypt(armored, SIG[1000000].slice(2)), /48 bytes/, "a short signature");
const future = timelockEncrypt(T.encode("not yet"), 5_000_000_000);
throwsWith(() => timelockDecrypt(future, SIG[2000000]), /does not open/, "a real, but earlier, beacon cannot open a future round");

// --- chunk boundaries (the age STREAM format), including the empty message
for (const len of [0, 1, 65535, 65536, 65537, 131073]) {
  const m = Uint8Array.from({ length: len }, (_, i) => (i * 31 + 7) & 255);
  const back = timelockDecrypt(timelockEncrypt(m, 1000000), SIG[1000000]);
  ok(back.length === len && back.every((x, i) => x === m[i]), `round trip at ${len} bytes`);
}
throwsWith(() => timelockEncrypt(new Uint8Array(MAX_PLAINTEXT + 1), 1000000), /too large/, "oversize message refused");
throwsWith(() => timelockEncrypt(T.encode("x"), 0), /round/, "round 0 refused");
throwsWith(() => timelockEncrypt(T.encode("x"), 2 ** 53), /round/, "unsafe round refused");

// --- the armor edge case: a last line of exactly 64 characters needs an empty line after it
{
  const bytesAt = (len) => Buffer.from(armored.split("\n").slice(1, -2).join(""), "base64").length - T.encode(secret).length + len;
  const want = (48 - (bytesAt(0) % 48)) % 48;
  const edge = timelockEncrypt(new Uint8Array(want), 1000000);
  ok(edge.endsWith("\n\n-----END AGE ENCRYPTED FILE-----\n"), "full last line is followed by an empty line");
  ok(timelockDecrypt(edge, SIG[1000000]).length === want, "and still opens");
  throwsWith(() => timelockDecrypt(edge.replace("\n\n-----END", "\n-----END"), SIG[1000000]), /not a time-lock file/, "without that empty line it is refused");
}

// --- tampering: every changed character is refused (header MAC, key check, or payload tag)
{
  const lines = armored.split("\n");
  let refused = 0, total = 0;
  for (let li = 1; li < lines.length - 2; li += 1) {
    for (const ci of [0, 17, 40]) {
      if (ci >= lines[li].length) continue;
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      const c = lines[li][ci];
      const swap = alphabet[(alphabet.indexOf(c) + 5) % 64];
      const copy = [...lines];
      copy[li] = lines[li].slice(0, ci) + swap + lines[li].slice(ci + 1);
      total++;
      try { timelockDecrypt(copy.join("\n"), SIG[1000000]); } catch { refused++; }
    }
  }
  ok(total > 10 && refused === total, `all ${total} single-character changes were refused`);
}

// --- format and trust: only the pinned chain, one stanza, the exact shape
const file = Buffer.from(armored.split("\n").slice(1, -2).join(""), "base64");
const rearm = (bytes) => { const b = Buffer.from(bytes).toString("base64").match(/.{1,64}/g); return `-----BEGIN AGE ENCRYPTED FILE-----\n${b.join("\n")}\n${b.at(-1).length === 64 ? "\n" : ""}-----END AGE ENCRYPTED FILE-----\n`; };
const text = file.toString("latin1");
ok(D.decode(timelockDecrypt(rearm(file), SIG[1000000])) === secret, "re-armoring the same bytes still works (test helper is sound)");
throwsWith(() => timelockDecrypt(rearm(Buffer.from(text.replace(QUICKNET.chainHash, "dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493"), "latin1")), SIG[1000000]), /different beacon/, "a file locked to another chain is refused");
throwsWith(() => timelockDecrypt(rearm(Buffer.from(text.replace("-> tlock 1000000", "-> tlock 1000001"), "latin1")), SIG[1000000]), /./, "changing the round in the header is refused");
throwsWith(() => timelockDecrypt(rearm(Buffer.from(text.replace("-> tlock", "-> scrypt"), "latin1")), SIG[1000000]), /not a time-lock file/, "another stanza type is refused");
throwsWith(() => timelockDecrypt(rearm(Buffer.from(text.replace("age-encryption.org/v1", "age-encryption.org/v2"), "latin1")), SIG[1000000]), /not a time-lock file/, "another version is refused");
throwsWith(() => timelockDecrypt(rearm(Buffer.from(text.replace("-> tlock 1000000", "-> tlock 01000000"), "latin1")), SIG[1000000]), /./, "a different spelling of the round is refused");
throwsWith(() => timelockDecrypt(rearm(file.subarray(0, file.length - 5)), SIG[1000000]), /./, "truncated payload is refused");
throwsWith(() => timelockDecrypt(rearm(Buffer.concat([file, Buffer.from("extra")])), SIG[1000000]), /./, "appended bytes are refused");
throwsWith(() => timelockDecrypt(armored + " ".repeat(2000), SIG[1000000]), /not a time-lock file/, "huge trailing whitespace is refused");
throwsWith(() => timelockDecrypt(armored.replace("\n", "\r\n"), SIG[1000000]), /not a time-lock file/, "wrong line endings are refused");
throwsWith(() => timelockDecrypt("", SIG[1000000]), /not a time-lock file/, "empty input");
throwsWith(() => timelockDecrypt("hello", SIG[1000000]), /not a time-lock file/, "plain text");
throwsWith(() => lockedRound(armored.slice(0, 200)), /not a time-lock file/, "truncated armor");
throwsWith(() => timelockDecrypt(null, SIG[1000000]), /not a time-lock file/, "not even a string");

console.log(`${n} checks passed`);

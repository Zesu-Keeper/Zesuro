// Tests for scripts/snapshot-core.mjs: hybrid (X25519 + ML-KEM-768) snapshot encryption.
// Run: node --no-warnings scripts/snapshot-core.test.mjs
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { generateRecovery, isRecoveryKey, openSnapshot, parseRecoveryKey, recoveryPublicOf, sealSnapshot, snapshotHeader } from "./snapshot-core.mjs";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const throws = (f, re, m) => { assert.throws(f, re, m); n++; };

const a = generateRecovery(), b = generateRecovery();
ok(parseRecoveryKey(a.publicKey)?.kind === "zk1" && isRecoveryKey(a.publicKey), "hybrid recovery key parses");
ok(recoveryPublicOf(a.secret) === a.publicKey, "its public half is recomputed from the secret");
ok(a.publicKey !== b.publicKey, "keys differ");
for (const bad of ["", "zk1.", "zk1.AAAA.BBBB", a.publicKey + "A", a.publicKey.replace("zk1", "zk2"), a.publicKey.slice(0, -2) + "AB".slice(0, 2)]) {
  if (bad !== a.publicKey) ok(!isRecoveryKey(bad), `rejects malformed key ${bad.slice(0, 12)}…`);
}

const plain = Buffer.from("SQLite format 3\0 " + "row".repeat(50000));
const meta = { at: 1700000000000, entries: { count: 3, tip: "a".repeat(64) }, comments: { count: 1, tip: "b".repeat(64) } };
const file = sealSnapshot(plain, a.publicKey, meta);
ok(file.subarray(0, 7).toString() === "ZSNAP2\n", "hybrid snapshots use the v2 format");
ok(!file.includes(Buffer.from("SQLite format")) && !file.includes(Buffer.from("rowrowrow")), "the plaintext does not appear in the file");
const opened = openSnapshot(file, a.secret);
ok(opened.plain.equals(plain) && opened.header.entries.count === 3 && opened.header.v === 2, "opens with the right key and returns the header");
ok(sealSnapshot(plain, a.publicKey, meta).equals(file) === false, "every snapshot is encrypted afresh");

// Wrong key, tampering
throws(() => openSnapshot(file, b.secret), /different recovery key/, "wrong recovery key");
const flip = (buf, at) => { const c = Buffer.from(buf); c[at] ^= 1; return c; };
throws(() => openSnapshot(flip(file, file.length - 40), a.secret), /auth|unable/i, "flipped ciphertext byte");
throws(() => openSnapshot(flip(file, file.length - 1), a.secret), /auth|unable/i, "flipped tag byte");
{ // header tampering: change the counts, which are authenticated as AAD
  const t = Buffer.from(file.toString("latin1").replace('"count":3', '"count":4'), "latin1");
  throws(() => openSnapshot(t, a.secret), /auth|unable/i, "edited header");
}
{ // swapping the ML-KEM ciphertext for another's must not open it
  const other = sealSnapshot(plain, a.publicKey, meta);
  const h1 = snapshotHeader(file), h2 = snapshotHeader(other);
  const mixed = Buffer.from(file.toString("latin1").replace(h1.header.ct, h2.header.ct), "latin1");
  throws(() => openSnapshot(mixed, a.secret), /auth|unable/i, "swapped KEM ciphertext");
}
throws(() => openSnapshot(file.subarray(0, 20), a.secret), /damaged|auth|unable|not a/i, "truncated");
throws(() => openSnapshot(Buffer.from("not a snapshot at all"), a.secret), /not a Zesuro snapshot/, "other file");
throws(() => sealSnapshot(plain, "nope", meta), /not a recovery key/, "bad recovery key refused when sealing");

// Older X25519-only keys still seal and open (ZSNAP1)
{
  const x = generateKeyPairSync("x25519");
  const pub = x.publicKey.export({ format: "jwk" }).x, pem = x.privateKey.export({ type: "pkcs8", format: "pem" });
  const old = sealSnapshot(plain, pub, meta);
  ok(old.subarray(0, 7).toString() === "ZSNAP1\n" && openSnapshot(old, pem).plain.equals(plain), "an X25519-only key still works");
  throws(() => openSnapshot(file, pem), /different recovery key/, "an old key cannot open a hybrid snapshot");
}

console.log(`All ${n} snapshot-core checks passed`);

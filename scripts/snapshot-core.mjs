// Encrypted snapshots of the whole database, so a standby server can pick up where a failed one
// left off. Only the holder of the recovery key (made by scripts/root.mjs, kept off the server)
// can open one; the servers that store snapshots can't.
//
// The recovery key is hybrid ("zk1"): X25519 AND ML-KEM-768 (FIPS 203). The snapshot key is derived
// from BOTH shared secrets, so an attacker must break both to read a snapshot. That matters here
// because a snapshot is kept for years by other machines: anything recorded today could be read
// later by a quantum computer if only X25519 protected it ("harvest now, decrypt later").
//
// File:  "ZSNAP2\n" + header JSON + "\n" + AES-256-GCM ciphertext + 16-byte tag
// Key:   HKDF-SHA256( ssX25519 || ssMLKEM, salt = SHA-256(ephemeral X25519 public || recovery X25519
//        public || ML-KEM ciphertext || ML-KEM public), info = "zesuro:snapshot:v2" ).
//        The header is authenticated with the ciphertext (AAD).
// Older files ("ZSNAP1": X25519 only) still open, and a recovery key without the ML-KEM half
// still seals them, so existing setups keep working. New ones should use zk1.
import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from "node:crypto";
import { ml_kem768 as KEM } from "@noble/post-quantum/ml-kem.js";

const MAGIC1 = Buffer.from("ZSNAP1\n"), MAGIC2 = Buffer.from("ZSNAP2\n");
const b64u = (b) => Buffer.from(b).toString("base64url");
const B64U = /^[A-Za-z0-9_-]+$/;
const x25519Pub = (x) => createPublicKey({ key: { kty: "OKP", crv: "X25519", x }, format: "jwk" });

/** Decode canonical unpadded base64url of an exact length, or null. */
function dec(s, len) {
  if (typeof s !== "string" || !B64U.test(s)) return null;
  const b = Buffer.from(s, "base64url");
  return b.length === len && b64u(b) === s ? b : null;
}

/** The public half of a recovery key: "zk1.<x25519>.<ml-kem-768>" (hybrid) or a bare 43-character X25519 key (older). */
export function parseRecoveryKey(key) {
  if (typeof key !== "string") return null;
  if (/^[A-Za-z0-9_-]{43}$/.test(key) && dec(key, 32)) return { kind: "x25519", x: key };
  const p = key.split(".");
  if (p.length !== 3 || p[0] !== "zk1" || !dec(p[1], 32) || !dec(p[2], KEM.lengths.publicKey)) return null;
  return { kind: "zk1", x: p[1], kem: p[2] };
}
export const isRecoveryKey = (k) => parseRecoveryKey(k) !== null;

/** Make a hybrid recovery key. `secret` is JSON text to keep off the server. */
export function generateRecovery() {
  const x = generateKeyPairSync("x25519");
  const kem = KEM.keygen();
  const xPub = x.publicKey.export({ format: "jwk" }).x;
  return {
    publicKey: `zk1.${xPub}.${b64u(kem.publicKey)}`,
    secret: JSON.stringify({ v: 1, alg: "zk1", x25519: x.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"), kem: b64u(kem.secretKey) }),
  };
}

function openRecoverySecret(text) {
  const s = Buffer.isBuffer(text) ? text.toString("utf8") : String(text);
  if (!s.trimStart().startsWith("{")) { // older PEM recovery key (X25519 only)
    const priv = createPrivateKey(s);
    return { kind: "x25519", priv, x: createPublicKey(priv).export({ format: "jwk" }).x };
  }
  const j = JSON.parse(s);
  if (j?.v !== 1 || j.alg !== "zk1") throw new Error("not a recovery key");
  const kemSecret = dec(j.kem, KEM.lengths.secretKey);
  if (!kemSecret) throw new Error("recovery key is damaged");
  const priv = createPrivateKey({ key: Buffer.from(String(j.x25519), "base64url"), format: "der", type: "pkcs8" });
  const x = createPublicKey(priv).export({ format: "jwk" }).x;
  return { kind: "zk1", priv, x, kemSecret, kem: b64u(KEM.getPublicKey(kemSecret)) };
}
/** The public recovery key that goes with a secret. */
export function recoveryPublicOf(secret) {
  const k = openRecoverySecret(secret);
  return k.kind === "zk1" ? `zk1.${k.x}.${k.kem}` : k.x;
}

const keyV1 = (shared, ephX, recX) => Buffer.from(hkdfSync("sha256", shared, Buffer.concat([Buffer.from(ephX, "base64url"), Buffer.from(recX, "base64url")]), "zesuro:snapshot:v1", 32));
const keyV2 = (ssX, ssK, ephX, recX, ct, kemPub) =>
  Buffer.from(hkdfSync("sha256", Buffer.concat([ssX, ssK]),
    createHash("sha256").update(Buffer.concat([Buffer.from(ephX, "base64url"), Buffer.from(recX, "base64url"), ct, Buffer.from(kemPub, "base64url")])).digest(),
    "zesuro:snapshot:v2", 32));

/** `meta` goes in the readable header (counts, tips, time): nothing private. */
export function sealSnapshot(plain, recoveryKey, meta) {
  const r = parseRecoveryKey(recoveryKey);
  if (!r) throw new Error("not a recovery key");
  const eph = generateKeyPairSync("x25519");
  const ephX = eph.publicKey.export({ format: "jwk" }).x;
  const iv = randomBytes(12);
  const ssX = diffieHellman({ privateKey: eph.privateKey, publicKey: x25519Pub(r.x) });
  let header, key, magic;
  if (r.kind === "zk1") {
    const { cipherText, sharedSecret } = KEM.encapsulate(Buffer.from(r.kem, "base64url"));
    magic = MAGIC2;
    header = Buffer.from(JSON.stringify({ v: 2, ...meta, recovery: recoveryKey, eph: ephX, ct: b64u(cipherText), iv: b64u(iv) }));
    key = keyV2(ssX, Buffer.from(sharedSecret), ephX, r.x, Buffer.from(cipherText), r.kem);
  } else {
    magic = MAGIC1;
    header = Buffer.from(JSON.stringify({ v: 1, ...meta, recovery: recoveryKey, eph: ephX, iv: b64u(iv) }));
    key = keyV1(ssX, ephX, r.x);
  }
  const c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(header);
  return Buffer.concat([magic, header, Buffer.from("\n"), c.update(plain), c.final(), c.getAuthTag()]);
}

export function snapshotHeader(file) {
  const magic = file.subarray(0, 7);
  if (!magic.equals(MAGIC1) && !magic.equals(MAGIC2)) throw new Error("not a Zesuro snapshot");
  const nl = file.indexOf(0x0a, 7);
  if (nl < 0 || nl > 8192) throw new Error("damaged snapshot header");
  const header = JSON.parse(file.subarray(7, nl).toString("utf8"));
  if (header.v !== (magic.equals(MAGIC2) ? 2 : 1)) throw new Error("damaged snapshot header");
  return { header, raw: file.subarray(7, nl), body: file.subarray(nl + 1) };
}

export function openSnapshot(file, recoverySecret) {
  const { header, raw, body } = snapshotHeader(file);
  const k = openRecoverySecret(recoverySecret);
  const mine = k.kind === "zk1" ? `zk1.${k.x}.${k.kem}` : k.x;
  if (header.recovery !== mine) throw new Error("this snapshot was made for a different recovery key");
  if (body.length < 16) throw new Error("damaged snapshot");
  let key;
  const ssX = diffieHellman({ privateKey: k.priv, publicKey: x25519Pub(header.eph) });
  if (header.v === 2) {
    if (k.kind !== "zk1") throw new Error("this snapshot needs a hybrid (zk1) recovery key");
    const ct = dec(header.ct, KEM.lengths.cipherText);
    if (!ct) throw new Error("damaged snapshot header");
    key = keyV2(ssX, Buffer.from(KEM.decapsulate(ct, k.kemSecret)), header.eph, k.x, ct, k.kem);
  } else {
    key = keyV1(ssX, header.eph, k.x);
  }
  const d = createDecipheriv("aes-256-gcm", key, Buffer.from(header.iv, "base64url"));
  d.setAAD(raw);
  d.setAuthTag(body.subarray(body.length - 16));
  return { header, plain: Buffer.concat([d.update(body.subarray(0, body.length - 16)), d.final()]) };
}

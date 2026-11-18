// The server's own signing key (the "writer" key the root key delegates to), used by anchor.mjs
// and snapshot.mjs. Two kinds:
//   Ed25519, in data/anchor-key.pem  (fast; what the site started with)
//   hybrid zs1 (Ed25519 + SLH-DSA), in data/anchor-key.json  (about 35 seconds of CPU per signature
//   and 10 KB per signature, so run anchors every 30 minutes or so; unforgeable even by a quantum
//   computer unless both halves are broken)
// data/anchor-key.pub holds the public key either way: this is what you give to `root.mjs delegate`.
import fs from "node:fs";
import path from "node:path";
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign } from "node:crypto";
import * as hybrid from "./hybrid-sig.mjs";
import { writerBytes } from "./log-core.mjs";

const b64u = (b) => Buffer.from(b).toString("base64url");

/**
 * Loads the writer key, making one if there is none. `wantHybrid` only matters when making one;
 * an existing key is never replaced (delegations name it).
 */
export function loadWriterKey(dataDir, { wantHybrid = false } = {}) {
  const pem = path.join(dataDir, "anchor-key.pem"), json = path.join(dataDir, "anchor-key.json"), pub = path.join(dataDir, "anchor-key.pub");
  if (fs.existsSync(pem) && fs.existsSync(json)) throw new Error("Both anchor-key.pem and anchor-key.json exist. Remove the one that is not delegated.");
  if (wantHybrid && fs.existsSync(pem)) throw new Error("This server already has an Ed25519 writer key, which delegations may name. Refusing to replace it; move it away deliberately if you mean to switch.");
  if (!fs.existsSync(pem) && !fs.existsSync(json)) {
    if (wantHybrid) {
      const k = hybrid.generate();
      fs.writeFileSync(json, k.secret, { mode: 0o600 });
      fs.writeFileSync(pub, k.publicKey + "\n", { mode: 0o644 });
    } else {
      const { privateKey, publicKey } = generateKeyPairSync("ed25519");
      fs.writeFileSync(pem, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
      fs.writeFileSync(pub, b64u(Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url")) + "\n", { mode: 0o644 });
    }
  }
  if (fs.existsSync(json)) {
    const secret = fs.readFileSync(json, "utf8"), publicKey = hybrid.publicKeyOf(secret);
    if (!fs.existsSync(pub)) fs.writeFileSync(pub, publicKey + "\n");
    return { kind: "hybrid", publicKey, sign: (purpose, text) => hybrid.sign(secret, purpose, text) };
  }
  const priv = createPrivateKey(fs.readFileSync(pem));
  const publicKey = createPublicKey(priv).export({ format: "jwk" }).x;
  if (!fs.existsSync(pub)) fs.writeFileSync(pub, publicKey + "\n");
  // Anchors keep their original form (the head text itself); other purposes carry their label in the signed bytes.
  return { kind: "ed25519", publicKey, sign: (purpose, text) => b64u(edSign(null, purpose === "anchor" ? Buffer.from(text) : writerBytes(purpose, text), priv)) };
}

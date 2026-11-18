// NOT part of the normal test run. Re-checks src/lib/timelock.ts against the reference
// implementation (tlock-js) and rewrites scripts/fixtures/timelock-tlockjs.json.
//
// tlock-js is never a dependency of Zesuro. To run this, install it somewhere else, from a
// lockfile you have vetted (node scripts/vet-package.mjs tlock-js@0.9.0), with scripts off:
//   mkdir /some/scratch && cd /some/scratch && npm init -y && npm install tlock-js@0.9.0 --ignore-scripts
//   ORACLE=/some/scratch node --no-warnings /path/to/zesuro/scripts/timelock-crosscheck.cjs
const path = require("path");
const fs = require("fs");
const oracle = process.env.ORACLE;
if (!oracle) { console.error("Set ORACLE to the folder where tlock-js is installed."); process.exit(64); }
const { timelockEncrypt, timelockDecrypt } = require(path.join(oracle, "node_modules/tlock-js"));
const CH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
const INFO = { public_key: "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a", period: 3, genesis_time: 1692803367, hash: CH, groupHash: "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e", schemeID: "bls-unchained-g1-rfc9380", metadata: { beaconID: "quicknet" } };
// Real, past beacons from api.drand.sh (the reference verifies them itself).
const BEACONS = {
  1000000: { round: 1000000, randomness: "b22aad4794f7451896f7a371aa46106fd84d919f3f569acd5b2fddf1d1440af3", signature: "83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72" },
};
const client = { options: {}, chain: () => ({ baseUrl: "fake", info: async () => INFO }), get: async (r) => { if (!BEACONS[r]) throw new Error("no such round " + r); return BEACONS[r]; } };
const log = console.log; console.log = () => {}; // the reference prints every beacon
(async () => {
  const { timelockEncrypt: ours, timelockDecrypt: oursOpen } = await import(path.join(__dirname, "../src/lib/timelock.ts"));
  const msg = "Interop vector: the reveal says what I said. ✓ é";
  const theirs = await timelockEncrypt(1000000, Buffer.from(msg), client);
  const big = Buffer.alloc(70000, 7); // two STREAM chunks
  const res = {
    referenceOpensItsOwn: (await timelockDecrypt(theirs, client)).toString() === msg,
    referenceOpensOurs: (await timelockDecrypt(ours(new TextEncoder().encode(msg), 1000000), client)).toString() === msg,
    weOpenTheirs: new TextDecoder().decode(oursOpen(theirs, BEACONS[1000000].signature)) === msg,
    weOpenTheirsTwoChunks: Buffer.from(oursOpen(await timelockEncrypt(1000000, big, client), BEACONS[1000000].signature)).equals(big),
    referenceOpensOursTwoChunks: (await timelockDecrypt(ours(big, 1000000), client)).equals(big),
  };
  console.log = log;
  console.log(JSON.stringify(res));
  if (!Object.values(res).every(Boolean)) process.exit(1);
  fs.writeFileSync(path.join(__dirname, "fixtures/timelock-tlockjs.json"), JSON.stringify({ msg, theirs }));
})().catch((e) => { console.log = log; console.error("FAILED:", e.stack || e); process.exit(1); });

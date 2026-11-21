# Audit brief

This brief is for an independent reviewer. Zesuro has had no outside audit. The code has been written, tested and reviewed only by the people who maintain it, so please assume nothing here has been checked by anyone else.

## What Zesuro is

A public, permanent record where people post something with an exact time and decide if and when their name is attached. There are no accounts. A browser makes a secret key, and that key is the only proof of authorship. The server keeps a hash-linked record, signs checkpoints of it, and stores things it should not be able to read: locked names, encrypted chat messages and locked private replies. Other people run mirrors that copy and check the record.

The people most at risk are anonymous sources and the journalists they talk to. The aim is that a source who follows the site's advice stays anonymous even if the site's operator turns hostile, and that nobody can quietly rewrite history.

## Who we defend against

- A curious or hostile site operator, including someone who seizes or compromises the server.
- Anyone watching the network, including the visitor's internet provider and the site's hosting company.
- An adversary who records encrypted traffic today and has a quantum computer later.
- Someone who later gets hold of a source's device and tries to read old chats or replies.
- Someone who serves modified site code to a visitor (the browser holds the keys, and the site serves the code that uses them).

## What we do not claim

- The time lock and the chat's older key exchange use BLS12-381 and P-256, which a quantum computer would break. The post-quantum parts are chat (ML-KEM-768), private replies (X25519 with ML-KEM-768) and the root key (Ed25519 with SLH-DSA).
- If enough drand operators collude, they could open a time lock early.
- A compromised browser or device defeats everything on it.
- Traffic analysis is only partly addressed. The site sees when a visitor connects and roughly when messages are sent.
- A post held by the delayed-release feature sits on the server in the clear for up to six hours.
- During development the root signing key is on the server. Launch requires a fresh offline key.

## What to review, in order of importance

**1. The record and who may write it**
- `scripts/log-core.mjs`: the full definition of both hash chains (entries use hash versions 3, 4 and 5; comments have their own chain). Anyone can re-implement it from this file.
- `src/lib/entries.ts` (`hashEntry`, `sealEntry`, `verifyChain`, `listLog`) and `src/lib/comments.ts`.
- `scripts/root.mjs`, `scripts/hybrid-sig.mjs`, `src/lib/writer.ts`, `scripts/authority.test.mjs`: the root key, delegations, and the rule that only the delegated server may write.
- `scripts/anchor.mjs`, `scripts/mirror.mjs`, `scripts/verify-log.mjs`: signed checkpoints, mirror countersigning and fork detection.
- `scripts/snapshot-core.mjs`, `scripts/restore.mjs`: encrypted snapshots and recovery.

**2. Authorship and commitments**
- `src/lib/commit.ts`, `src/lib/opening.ts`, `src/lib/client-crypto.ts`, `src/lib/secret.ts`: per-post Ed25519 keys, salts, and the commitment that covers the post's exact content.
- `src/lib/phrase.ts`: six-word keys (66 bits, Argon2id). Is that strength acceptable for the cost parameters?

**3. Time locks**
- `src/lib/timelock.ts`, `src/lib/beacon.ts`, `src/lib/release-bundle.ts`: encryption to a future drand round. It is meant to be compatible with the reference tool `tle`; `scripts/timelock-crosscheck.cjs` and `scripts/timelock.test.mjs` check that.

**4. Private chat**
- `src/lib/chat-crypto.ts`: invite handshake, safety code, message framing, identity proofs.
- `src/lib/chat-ratchet.ts`: the Double Ratchet with an ML-KEM-768 layer. State is a pure function so a failed message cannot corrupt it.
- `src/lib/chat-store.ts`, `src/lib/chat-session.ts`: session-only chats, the optional Argon2id passcode, auto-lock, erase.
- `src/lib/chat.ts`, `src/app/api/chat`: what the server stores, deletion, padding, retention.
- `src/lib/thread-crypto.ts`: private follow-up comments from an author.

**5. Private replies**
- `src/lib/mailbox.ts`: twelve monthly hybrid key pairs sealed into the post, fingerprint covered by the record.
- `src/lib/inbox.ts`, `src/app/api/inbox`: the shared feed every visitor fetches. Does fetching reveal anything about who the reader is?
- `src/lib/journalist.ts`, `src/lib/newsroom.ts`: verified journalist identities through a newsroom's published file.

**6. Delivery of the code**
- `scripts/release.mjs`, `scripts/code-check.mjs`, `src/lib/release-log.ts`, `scripts/release-log-core.mjs`: signed releases and the append-only release log.
- `src/middleware.ts`: the content security policy and the private chat host handling.
- `extension/` and `scripts/build-extension.mjs`: the browser add-on that carries its own copy of the chat code.

**7. Everything else that handles keys**
- `src/lib/transfer.ts`: the encrypted bundle used to move keys between addresses.
- `src/components/KeyBackup.tsx`, `src/app/mine`, `src/app/phrase`.
- `src/lib/http.ts`, `src/lib/spam.ts`, `src/lib/ticket*.ts`: rate limits and the spam ticket.

## How to run it

Node 22.18 or newer. After `npm ci --ignore-scripts`:

```
node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/<name>.test.mjs
```

Useful test names: `chat-ratchet`, `chat-crypto`, `chat-store`, `mailbox`, `inbox-wire`, `timelock`, `timelock-wire`, `authority`, `writer`, `phrase`, `transfer`, `identify`, `delay`, `release-log`, `snapshot-core`, `recovery`. The record can be checked from outside with `scripts/verify-log.mjs` and `scripts/code-check.mjs` (see the technical guide). `SPEC.md` and `deploy/RUNBOOK.md` describe the design and operation.

## Questions we most want answered

1. Can a hostile operator learn who wrote a post, or link two posts to the same author, from anything the server holds or sees?
2. Are the commitments and the hash versions sound? Can a reveal be forged, or a post be re-attached to different text or a different author?
3. Is the Double Ratchet with the ML-KEM layer implemented correctly, including state handling, skipped messages and the handshake?
4. Does the private reply feed leak anything about readers or authors? Are the monthly key rotation and erasure sound?
5. Is the time lock safe to rely on, and does it fail safe when the beacon is unavailable or wrong?
6. Can modified site code get past `code-check` and the release log, and what stops a first-time visitor being served bad code?
7. Is the key handling in the browser (storage, backup, six-word keys, transfer bundle, passcode) as safe as it can be in a web page?
8. Anything in the server code that allows rewriting history, bypassing the write rule, or denying service cheaply.

## What we would like back

A written report with severity ratings, reproductions for anything you find, and your view of what is out of reach for a web application. Please contact the maintainers privately first so problems can be fixed before they are published.

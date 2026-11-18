# Zesuro: keeping the record alive, and proving it

One server writes the record at a time: the one the **root key** has delegated to. If that server
is lost, anyone holding the root key can delegate to another, and the record continues from where
mirrors and snapshots have it. Nobody without the root key can make a server count.

## Once (on your own computer, not the server)
1. `node scripts/root.mjs init --dir zesuro-root` (makes the hybrid root key and recovery key).
   Keep **two offline copies** of `zesuro-root/`. Losing it means no replacement server can ever be authorised.
2. Get the server's writer key: `cat /opt/whenisaid/app/data/anchor-key.pub` (run `node scripts/anchor.mjs` first if absent).
   For a writer key that a quantum computer could not forge either, make it hybrid instead: `node scripts/anchor.mjs --hybrid` on a server that has no key yet. Each signature then takes about 35 s of CPU and 10 KB, so run the cron every 30 minutes (below) and not every 5.
3. `node scripts/root.mjs delegate --writer <that key> --from genesis --dir zesuro-root --authority authority.json`
   (`genesis` so anchors the server signed before delegations existed are covered).
4. Copy `authority.json` to the server's `data/`. Give mirrors your root public key **out of band** (not from the site).
5. On each deploy: build, then `node scripts/release.mjs hash`, look at the list, `node scripts/release.mjs sign --draft release-draft.json --dir zesuro-root`, copy `release.json` to `data/`.
6. On the server: install `deploy/cron.d/zesuro-record`. While `data/authority.json` exists, the server accepts new entries and comments only if its own key is the delegated writer; a replacement is read-only until you delegate to it.

## Mirrors and standbys (another machine, ideally someone else's)
`node scripts/mirror.mjs https://zesuro.com --dir mirror --root <root key> --witness --standby --watch 300`
It prints its key; the operator accepts it with `node scripts/admin.mjs witness-add <key> <name>`.
Check the site's code: `node scripts/code-check.mjs https://zesuro.com --root <root key>`.
Anyone can run `node scripts/verify-log.mjs https://zesuro.com --root <root key>`.

## If the server is lost
1. New machine, same app code. Take the standby's `snapshots/` (and its mirror folder).
2. `node scripts/restore.mjs --snapshot <file.zsnap> --recovery zesuro-root/recovery-key.json --manifest <latest.json> --root <root key> --authority authority.json --log <mirror folder> --data data`
   It refuses a snapshot whose manifest the root's delegations do not vouch for.
3. Start the app once (it is read-only: its key is not delegated yet), run `node scripts/anchor.mjs` (makes this server's key), then on your computer:
   `node scripts/root.mjs delegate --writer <new key> --from <mirror folder> --dir zesuro-root --authority authority.json`
   and copy the new `authority.json` over. Point DNS here. Mirrors follow; the old server can no longer sign.
4. Entries made in the last minutes before the failure come back public-parts only (a dated reveal among them will not fire by itself; comment text is lost).

## Another domain
Run the app there as a mirror first. People move their keys with `/transfer` on each address. Only the
delegated server accepts posts; a second address becomes a writer only when you delegate to it.

## Time-locked reveals

A dated or locked entry's author name and hidden parts are encrypted in the author's browser to a drand
round (`src/lib/timelock.ts`), so the server holds only ciphertext and cannot read them early. When the
round is published the server fetches the beacon, checks it against the pinned quicknet key, opens the
lock, and checks the result against the entry's commitment, all on the next page view.

- The server asks public drand relays. To use your own list: `ZESURO_DRAND_URLS=https://a.example,https://b.example`
  in the service's environment (HTTPS only). A relay is never trusted: signatures are verified.
- The chain (hash version 4) covers the SHA-256 of each lock, so a lock can't be swapped later. A lock's
  ciphertext is public in the log only when the author chose a public reveal date, or after the reveal,
  because it carries the unlock round. A private-date lock is held by the server alone until then.
  Locks over about 14 KB (a very long hidden passage) are never published in the log, only their hash.
- **Anyone can open a due lock without the server**, from a mirror's copy of the log:
  `node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/timelock-open.mjs --log <mirror folder>`.
  It also re-checks every reveal the server has made. Run it now and then against your mirror.
- A lock that does not hold a valid opening (a broken or hostile browser) is marked failed and never reveals.
- Not quantum-safe (BLS12-381), and a threshold of colluding drand operators could open a lock early.

## Mirrors and impostors (a root-signed directory)

The root signs two lists: **mirrors** it vouches for, and **impostors** (sites or keys that are not part of the
record and must not be trusted to sign or publish anything here). On the machine with the root key:

    node scripts/sites.mjs add-mirror --url https://mirror.example --name "Name" [--key <site key>]
    node scripts/sites.mjs add-malicious --url https://fake.example [--key <key>] --reason "why"
    node scripts/sites.mjs sign --dir zesuro-root --out sites.json

Copy `sites.json` to the server's `data/`; it is served at `/api/sites` and shown on `/sites`. Each signing raises
a serial number, so a checker that remembers the highest serial it has seen refuses an older list. Check a list
with `node scripts/sites.mjs verify --file sites.json --root <root key>`. A site cannot be in both lists. The
`/sites` page only displays the lists; do not trust it, verify the file against a root key you got elsewhere.

## What this does not fix
Dated reveals made before time-locks existed (and by stale open pages, which the server still accepts) are held in
plaintext by the server until their date. A private reveal date keeps its ciphertext off the public log, so only
the server holds it until the reveal. Code checks can be
evaded for a targeted visitor. Mirrors only help if people other than the operator run them.

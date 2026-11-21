# Zesuro technical guide

This guide is for people who want to check the record, run a mirror, or host a server. If you only want to use the site, read the [help page](/help) instead. The code is at [github.com/Zesu-Keeper/Zesuro](https://github.com/Zesu-Keeper/Zesuro).

## Verifying the record

You do not have to trust the site. These tools need only Node 22.18 or newer and are in the `scripts` folder of the project.

Check the whole public record and its signatures against the root key:

```
node scripts/verify-log.mjs https://zesuro.com --root <root public key>
```

Check that the scripts and styles the site serves are the ones the root signed:

```
node scripts/code-check.mjs https://zesuro.com --root <root public key>
```

Open any time-locked entry whose round has passed, from a mirror's copy, without the server:

```
node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/timelock-open.mjs --log <mirror folder>
```

Get the root public key from somewhere other than the site. The file `deploy/ROOT-KEY.txt` in the repository holds it, and the Mirrors page shows what the site says it is. Compare the copies before you trust any of them.

### Mirrors

The Mirrors page lists sites the root key approves as faithful copies, and any sites or keys it says are not connected to Zesuro. The list is signed, but the page only displays it. Check the signed file yourself:

```
node scripts/sites.mjs verify --file sites.json --root <root public key>
```

### Checking who wrote a post

Every post shows a commitment. The author makes a key just for that post, so the commitment covers the post's exact words. When the author reveals, the post page shows a public key, a salt and a signature. To check it, work out the SHA-256 of `zesuro:commit:v2:<public key>:<salt>:<SHA-256 of the content>` and compare it with the commitment. The post page lists the content string and its hash. Then check the Ed25519 signature over `whenisaid:reveal:v2:<post id>:<name>` with the same public key. Older posts, made before commitments covered the content, only show that the author holds the key: SHA-256 of the public key and salt equals the commitment.

### Moving keys between addresses

The Move your keys page packs everything the browser holds for Zesuro into one bundle and encrypts it with a key made from a separate code. Nothing is sent to a server. The importing side adds only keys it does not already have, and refuses to replace its own device key. The code is in `src/lib/transfer.ts`.

### Private chat in detail

Both browsers make their chat keys locally and agree on them through the invite link (ECDH on P-256, with the link's secret mixed in). From that shared secret each chat runs a Double Ratchet: fresh Diffie-Hellman keys are exchanged as the two people reply, a chain key steps for every message, and each message key is used once and erased. A message can therefore be opened only once, so each device keeps the chat's history locally. A copy of the ratchet state on a second device would break it, so chats cannot be moved between devices. The creator sends an invisible first message so the opener can reply at once. The server stores only encrypted, padded messages and hashes of secrets. Ending a chat marks the room as deleted, removes its messages, and leaves a small marker for 30 days so the other side learns it ended. A browser that sees the marker erases its own key. With a passcode set, the chat index, chat state and history are encrypted on the device with AES-256-GCM under a key from PBKDF2-SHA256 (600,000 rounds); the key lives only in memory and is dropped after the idle time. Session-only chats live in session storage. The code is in `src/lib/chat-crypto.ts`, `chat-ratchet.ts`, `chat-session.ts`, `chat-store.ts` and `chat.ts`.

## Hosting your own server

You can run a private copy to read and check the record. To serve a copy to other people, your address has
to be on the root key's signed list of mirrors, and the software has to be unmodified (see the LICENSE file).
Ask the owner to list you. `mirror.mjs --serve` checks that list and refuses to serve an address that is not on it.

### What you need

- A Linux server with at least 1 GB of memory (a build wants more, so use swap or build elsewhere), a domain name, and root access.
- Node 22.18 or newer. The app uses the SQLite that comes with Node.
- nginx, and certbot for a certificate. Sealing only works over HTTPS.
- Optional: Tor, if you want an onion address.

### Install

```
git clone <repository> /opt/zesuro/app
cd /opt/zesuro/app
npm ci --ignore-scripts
npm run build
```

Make a separate user to run it, and give that user the app folder.

```
useradd --system --home /opt/zesuro zesuro
chown -R zesuro:zesuro /opt/zesuro
```

### Run it with systemd

Create `/etc/systemd/system/zesuro.service`:

```
[Unit]
Description=Zesuro
After=network.target

[Service]
User=zesuro
WorkingDirectory=/opt/zesuro/app
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=HOSTNAME=127.0.0.1
Environment=TRUST_PROXY=xff
ExecStart=/usr/bin/node node_modules/next/dist/bin/next start
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/zesuro/app/data /opt/zesuro/app/.next/cache
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Then `systemctl enable --now zesuro`. The app listens only on 127.0.0.1. The database lives in `data/` under the app folder, and it is created on first start.

Never expose `npm run dev` to the internet.

### nginx and HTTPS

Point your domain at the server, then proxy to the app. A minimal site file:

```
server {
    listen 443 ssl;
    server_name example.org;
    ssl_certificate     /etc/letsencrypt/live/example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.org/privkey.pem;

    access_log off;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Get the certificate with certbot using the webroot method and let it renew itself. Turn access logging off if you want the same property as zesuro.com: no visitor addresses are written anywhere.

Set `TRUST_PROXY` to match your proxy (see Settings).

### Settings

| Variable | What it does |
| --- | --- |
| `TRUST_PROXY` | How to read the caller's address: `xff` or `cloudflare`. |
| `ZESURO_DRAND_URLS` | Comma separated HTTPS addresses of drand relays to use for time locks. The defaults are public relays. |
| `DATA_DIR` | Where the scripts find the database, if it is not `data` in the current folder. |

### Backups

Copy `data/whenisaid.db` regularly. Use SQLite's own copy, not a plain file copy while the site is running:

```
node --no-warnings -e 'const {DatabaseSync}=require("node:sqlite");const d=new DatabaseSync("data/whenisaid.db",{readOnly:true});d.exec("VACUUM INTO \x27backup.db\x27")'
```

Keep the copies on another machine. A backup on the same disk does not survive the disk.

### Updating

Back up the database, build the new version away from the running one if memory is tight, stop the service, swap the build in, and start it. Keep the old build until you are sure the new one works. The first start after an update adds any new database columns by itself.

### An onion address

Install Tor and add a hidden service that points at a local port which nginx serves over plain HTTP. Back up the hidden service folder, because the address is its key.

## Keeping the record alive

One server writes the record at a time. The root key decides which one. Everything else is a mirror or a standby.

### The root key

Make it on your own computer, not on a server:

```
node scripts/root.mjs init --dir zesuro-root
```

This makes two secret files. `root-key.json` signs delegations, release lists and the mirrors list. `recovery-key.json` opens snapshots. Keep two offline copies of both. If you lose the root key, nobody can ever authorise a replacement server.

### Authorise the server

Find the server's writer key in `data/anchor-key.pub` (run `node scripts/anchor.mjs` once if it is missing). On your computer:

```
node scripts/root.mjs delegate --writer <that key> --from genesis --dir zesuro-root --authority authority.json
```

Copy `authority.json` to the server's `data/` folder. From then on the server accepts new entries and comments only while its own key is the delegated writer.

### Sign each release

After each build, list the scripts and styles with `node scripts/release.mjs hash`. Then sign the list on the machine that holds the root key, in one command:

```
node scripts/publish-signed.mjs user@your.server
```

It fetches the draft, signs it, and uploads `release.json`. The private key never leaves your computer. The deploy refuses to go ahead unless `release.json` is signed by the root key and matches the staged build exactly. People use the signed list to check what the site serves.

### Publish the list of mirrors and impostors

```
node scripts/sites.mjs add-mirror --url https://mirror.example --name "Name"
node scripts/sites.mjs add-malicious --url https://fake.example --reason "why"
node scripts/sites.mjs sign --dir zesuro-root --out sites.json
```

The same `publish-signed.mjs` command signs and uploads this list too when a `sites-draft.json` is next to you. Copy `sites.json` to `data/` if you do it by hand. Each signing raises a serial number so an old list cannot be replayed.

### Anchors and snapshots

Install `deploy/cron.d/zesuro-record` as `/etc/cron.d/zesuro-record`. It signs the chain tip and writes encrypted snapshots on a schedule. Copy the snapshots to another machine as well.

### Run a mirror

A mirror keeps its own copy of the public record and checks it. Run one on a machine that is not yours if you can. A mirror run by the same person as the site proves little.

```
node scripts/mirror.mjs https://zesuro.com --dir mirror --root <root public key> --witness --standby --watch 300
```

To serve your copy to others, add `--serve <port> --public-url https://your.address`. It starts only if the root's list names that address.

It raises an alert if the site rewrites history, serves less than it did before, or signs a tip that does not match the record. The site operator accepts its signing key with `node scripts/admin.mjs witness-add <key> <name>`.

### If the server is lost

1. Set up a new machine with the same app code.
2. Take a snapshot from a standby, then restore it:

```
node scripts/restore.mjs --snapshot <file.zsnap> --recovery zesuro-root/recovery-key.json --manifest <latest.json> --root <root key> --authority authority.json --log <mirror folder> --data data
```

3. Start the app. It is read only until you delegate to it.
4. Run `node scripts/anchor.mjs` to make its key, then delegate to that key from your computer and copy the new `authority.json` over.
5. Point the domain at the new server. Mirrors follow. The old server can no longer sign.

Entries made in the last minutes before the failure may come back with public parts only. A dated reveal among them will not fire by itself.

### A second domain

Run the app there as a mirror first. People move their keys with the Transfer page. A second address becomes a writer only when you delegate to it.

## Troubleshooting

### The page says writing is not allowed

The server's writer key does not match the last delegation. Delegate to the right key.

### A dated reveal did not open

The round may not be published yet, or the relays are unreachable. The server tries again later.

### The chain check fails

Do not fix it by hand. Compare with a mirror, find the first entry that differs, and restore from a snapshot if the database was damaged.


## How the cryptography fits together

### The pieces
- **Entries** are signed in the browser with a per-entry key. The server stores a commitment that covers the title, text, place and mode, so the author can later prove authorship without an account.
- **The record** is a hash chain over every entry and comment (`/api/chain`). Changing anything breaks every later hash.
- **Anchors** are signed tips of that chain, countersigned by independent mirrors.
- **Time locks** use the drand quicknet beacon with identity based encryption (the same scheme as the `tle` tool). The implementation is `src/lib/timelock.ts`, built on the audited `@noble` libraries, and it opens files made by the reference implementation.
- **Root key and delegations** are hybrid Ed25519 and SLH-DSA, so a quantum computer would need to break both. Snapshots are encrypted to a hybrid X25519 and ML-KEM-768 recovery key.
- **Chat** is end to end encrypted between browsers with a Double Ratchet, so it has forward secrecy and heals after a brief compromise. The ratchet state and history are kept on the device, optionally under a passcode.

### Six-word keys

A six-word key is a device key made from six words, so it can be remembered or written on paper. The words are six random picks from the 2048-word BIP-39 English list, which is 66 bits. They are joined with spaces and run through Argon2id (3 passes, 32 MB, one lane, salt `zesuro:six-word-key:v1`) to give 48 bytes. Those bytes, reduced modulo the P-256 group order minus one and then increased by one, are the private scalar. From there the key works like any other device key, so entry keys and salts derive from it as usual. The 66 bits are only safe because every guess costs a second and 32 MB, and only when the words are random, so the page only offers generated words. The key check code is the first two bytes of SHA-256 over `zesuro:key-check:v1:` plus the canonical public key JSON, shown in hex so a typing mistake is noticed. The code is in `src/lib/phrase.ts`.

### Where to read more
- [Specification](https://github.com/Zesu-Keeper/Zesuro/blob/main/SPEC.md)
- [Operator runbook](https://github.com/Zesu-Keeper/Zesuro/blob/main/deploy/RUNBOOK.md)
- [Time lock implementation](https://github.com/Zesu-Keeper/Zesuro/blob/main/src/lib/timelock.ts)
- [drand](https://drand.love), the public randomness beacon used for time locks

## Known limits

### What is not solved
Zesuro is an early project. The permanent record can be filled with spam or abuse, and the only response today is a public flag. The site's code is served by the site, so visitors trust it unless they run the code check. BLS12-381, used by the time lock and chat, is not quantum safe. The cryptography has been tested against reference implementations but has not had an outside audit.

# Zesuro help

Zesuro is a public record of statements. You write something, seal it, and it is stored with the exact time it was sealed. Nobody can edit or delete it afterwards. Your name is not attached unless you choose to attach it, and you choose when.

This guide covers using the site, what protects you and what does not, running your own server, and keeping the record alive if a server is lost. Read the security section before you rely on the site for anything that could put you at risk.

## Using the site

### Sealing a statement

Open the Say page, write a title and the text, and choose when your name will be revealed. Then press Seal. From that moment the text and the time are part of the public record. You cannot change them, and neither can the site operator.

Your first statement creates a key in your browser. The key is what proves later that you wrote the statement. There is no account and no password. If you clear your browser data without a backup, you lose the ability to prove authorship of everything you sealed with that key.

Back up your key. The site makes you save a backup code before a manual entry is sealed. Treat that code like a password. Anyone who has it can prove they wrote your statements.

### When your name is revealed

You pick one of these when you seal:

- **Decide later.** The statement is public and anonymous. You reveal your name yourself, whenever you like, from My entries.
- **On a date.** Your name is revealed automatically at the time you choose. Before that moment nobody, including the server, can read it. See "Time-locked reveals" below.
- **No matter what.** Like a date, but it cannot be stopped once sealed.
- **A deadline.** For a manual entry you can set a date after which the entry is marked Unknown if you have not revealed.

A name is a claim that is proven by the same key that sealed the entry. It is not an identity check. Anyone can type any name, so a revealed name is only as believable as the person who revealed it.

### Hiding parts of the text

Wrap words in double square brackets, like `[[this]]`, or select words and use the hide button. The public sees a block in their place. The hidden words open at the same moment your name does, and the record contains a hash that proves they were not changed.

### Adding a place

You can add a map pin. You can show it straight away or hide it until the reveal.

### Time-locked reveals

For a date or a no matter what entry, your browser encrypts your name and any hidden parts so that they can only be opened once a particular round of the drand randomness beacon is published. The server only ever holds the encrypted data. When the round arrives, the server opens it and checks the result against what you sealed. Anyone else can do the same without the server, using the tool described in the verification section.

Two things to know. First, it cannot be undone once you seal. Second, if you chose a private reveal date, the encrypted data stays off the public log until the reveal, because the round number would show the date.

### Reading, commenting and voting

The front page lists statements. You can search by words and by the date they were sealed. Each entry has its own page.

- You can comment on an entry. Comments are part of the record too.
- You can like or dislike an entry, and vote on whether the thing described did happen. These votes use a token tied to the entry, not to you, and you cannot vote twice from the same browser.
- You can flag an entry as spam. Flags are a public count. They push an entry down the ranking but do not remove it. Nothing is removed automatically.
- Similar entries are grouped on a page of their own.
- The Called it page lists revealed entries, ranked by how many people say the thing really happened. You can vote once an entry is revealed, one vote per browser.

### My entries

My entries shows everything sealed with the key in this browser. From there you can reveal a name, add a follow-up, and see the state of each entry. If you changed device or browser, use the key restore to paste your backup.

### Moving to another device or address

The Transfer page makes a sealed bundle of your keys with a code. Open the Transfer page on the other device or domain, paste the bundle, and enter the code. Use this when the site moves to a new address as well.

## Private chat

The chat is for a source who wants to talk to a reporter without being identified. It is end to end encrypted in the browsers, so the server only stores messages it cannot read.

How it works:

1. The person who wants to be contacted starts a private chat and makes a link. The link can be used once, a set number of times, or without limit.
2. They give the link to the person they want to talk to, by any channel they trust.
3. When the other person opens the link, the two browsers agree on a key. Each side sees a safety code. Compare the code over a different channel, for example by voice, to be sure nobody sits in the middle.
4. Either side can prove inside the chat that they sealed a particular public entry. The proof is a signature, so the reporter can check that the person they are talking to wrote the statement, without learning who that person is.
5. A chat can have a delete timer, and either side can delete the chat.

Limits: text only. There is no forward secrecy, so if a chat key is stolen later, old messages in that chat can be read. The server can see that a chat exists and roughly when messages arrive. If your threat is a state, use the onion address (see below) and a clean device.

## Security

### What protects you

- **No accounts and no tracking.** Authorship is proved by a signature. The server does not log visitor addresses.
- **Anonymous by design.** Each entry has its own commitment, so two of your entries cannot be linked to each other from the public record.
- **A tamper-evident record.** Every entry and comment feeds into a hash chain. Changing or removing anything breaks every hash after it.
- **Signed tips.** The server signs the state of the chain every few minutes. Independent mirrors keep their own copy and countersign, so a rewrite would be caught.
- **Time locks.** Dated reveals are held by a public beacon, not by the operator.
- **Strict page security.** A content security policy, no raw HTML, and rate limits on posting.

### What does not protect you

- **The site's own code.** Your key is created and used by JavaScript that the server sends. A hostile or compromised server could send code that steals keys or skips the encryption. Run a code check (below), prefer a mirror you trust, and keep sensitive work to the onion address or a copy you built yourself.
- **Your device.** Malware or a hostile browser extension can read your key. The backup code is equally sensitive.
- **Your network.** The site cannot hide that you visited it from your internet provider. Use Tor for that.
- **What you write.** Details in the text can identify you. Wording, places, times and facts that only a few people know are the usual ways sources are found.
- **Quantum computers.** The time lock and chat use elliptic curves that a large quantum computer could break. The signing keys of the root and the writer are hybrid and also use a post-quantum scheme.
- **Beacon collusion.** If enough drand operators colluded, they could open a time lock early.
- **A name is not proof of identity.** See above.

### Being careful in practice

Use the Tor Browser if you are worried about being traced. Do not post from a work device or network. Write the text with care about what it reveals. Keep your key backup offline. Do not tell anyone which entries are yours unless you have chosen to.

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

### Mirrors and impostors

The Mirrors page lists sites the root key vouches for as faithful copies, and sites or keys it names as impostors. The list is signed, but the page only displays it. Check the signed file yourself:

```
node scripts/sites.mjs verify --file sites.json --root <root public key>
```

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

With `TRUST_PROXY=xff` the app takes the caller's address from the header nginx sets. Without it every caller shares one rate-limit bucket. Use `TRUST_PROXY=cloudflare` behind Cloudflare.

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

Install Tor and add a hidden service that points at a local port which nginx serves over plain HTTP. Back up the hidden service folder, because the address is its key. Tell nginx to add an `X-Onion` header so the app knows the request came by Tor.

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

Copy `authority.json` to the server's `data/` folder. From then on the server accepts new entries and comments only while its own key is the delegated writer. Removing the file lifts that rule.

### Sign each release

After each build, list the scripts and styles, look at the list, and sign it:

```
node scripts/release.mjs hash
node scripts/release.mjs sign --draft release-draft.json --dir zesuro-root
```

Copy `release.json` to `data/`. People use it to check what the site serves.

### Publish the list of mirrors and impostors

```
node scripts/sites.mjs add-mirror --url https://mirror.example --name "Name"
node scripts/sites.mjs add-malicious --url https://fake.example --reason "why"
node scripts/sites.mjs sign --dir zesuro-root --out sites.json
```

Copy `sites.json` to `data/`. Each signing raises a serial number so an old list cannot be replayed.

### Anchors and snapshots

Install `deploy/cron.d/zesuro-record` as `/etc/cron.d/zesuro-record`. It signs the chain tip every five minutes and writes an encrypted snapshot every fifteen. Copy the snapshots to another machine as well.

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

## Problems

**The page says writing is not allowed.** The server has an `authority.json` that names a different writer key, or its own key file is missing. Check `data/anchor-key.pub` against the last delegation, or delegate to the right key.

**A dated reveal did not open.** The round may not be published yet, or the relays are unreachable. The server tries again on the next page view. If the lock holds something that is not a valid opening, it is marked failed and will never reveal.

**The chain check fails.** Do not fix it by hand. Compare with a mirror, find the first entry that differs, and restore from a snapshot if the database was damaged.

**You lost your key.** There is no recovery. Nobody, including the operator, can prove you wrote your entries without it.

**A post is refused as too fast.** The server rejects posts sent implausibly quickly. Wait a few seconds and try again.

## Limits to keep in mind

Zesuro is an early project. The permanent record can be filled with spam or abuse, and the only response today is a public flag. The site's code is served by the site, so you are trusting it unless you check. The cryptography has been tested against reference implementations but has not had an outside audit. Do not rely on it alone where your safety depends on it.

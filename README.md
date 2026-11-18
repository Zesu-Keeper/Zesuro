# Zesuro

Say it now. It's recorded, with its exact time. You decide when your name is attached.

When someone asks "did you really say that?", the record answers.

- Write a statement and tap **Seal**. It can't be edited or deleted.
- The text is public straight away. Who said it stays hidden until the author reveals.
- Reveal manually, on a date, or lock it ("no matter what") so nothing can stop it.
- Zesuro records who said what, and when, anonymously, but with verification.

Status: early prototype. See [SPEC.md](SPEC.md) for the full specification.

## Run it

Needs Node 22.18 or newer (the prototype uses Node's built-in SQLite).

```
npm install
npm run dev          # http://localhost:3000
```

Production build: `npm run build && npm start`.

End-to-end test (server must be running; takes about 40 seconds because it waits for a
locked reveal to fire):

```
npm run smoke
```

Data lives in `data/whenisaid.db`. Delete the `data` folder to start fresh.

## What works today

- Seal screen, reveal options sheet, public record, entry pages, "My entries"
- Per-device secret key, unlinkable per-entry author commitments, reveal with proof
- Modes: decide later, on a date, no matter what (locked), an optional deadline, after which it shows as Unknown
- Mandatory key-backup QR before a manual entry is sealed; key restore by pasting text
- A public title on every entry, links in the text, search by words and by sealed date range
- Redaction: wrap words in `[[double brackets]]` (or select them and tap "Hide selected words").
  The public sees a block until the entry is released; only a hash of the hidden text is chained.
- Optional map pin (OpenStreetMap), shown now or hidden until release. Hidden text and place
  open at the same moment as the author's name.
- Hash chain over all entries (`/api/chain`) so history can't be rewritten quietly

## Security

Built in:
- All database access is parameterised. No raw HTML is ever rendered; links are added as real
  elements for `http(s)` only.
- Content-Security-Policy with a per-request nonce, plus `nosniff`, frame denial, a strict
  referrer policy and HSTS (production). The author's key lives in browser storage, so
  script injection is treated as key theft.
- Requests: JSON only, 100 KB cap, per-caller rate limits (sealing is limited per minute
  and per day), and a cached, rate-limited chain check.
- Text, titles, names and places reject hidden direction-control and control characters, so
  a record cannot be made to read differently from what was sealed.
- Authorship is proved by a signature, never by a cookie or login, so there is nothing for
  cross-site request forgery to ride on.

Before going live:
- Run a production build (`npm run build && npm start`). Never expose `npm run dev`.
- Set `TRUST_PROXY=cloudflare` (or `xff` behind one proxy that appends the real address) so
  rate limits see real callers. Without it all callers share one bucket.
- Serve over HTTPS only (sealing needs it) and keep `data/` on a persistent disk that is
  backed up and not web-accessible. Replace the in-memory rate limiter with an edge limiter.
- Keep Node on the latest 22.x security release.

Known limits:
- Dated and locked reveals are time-locked: the browser encrypts the name and hidden parts to a drand
  round (`src/lib/timelock.ts`), so the server cannot read them early. It can still be slow to open them,
  and the ciphertext stays in the record for anyone to open once the round has passed. A threshold of
  colluding drand operators could open one early, and BLS12-381 is not quantum-safe. Entries sealed
  before this existed were held by the server in plaintext.
- A name is a claim proven by the same key, not an identity check; anyone can type any name.
- The key sits in browser storage, so malware or a malicious extension on the device could read
  it. The backup QR is equally sensitive.
- The permanent record can be filled with spam or abusive text. Removals are legal-only
  (see SPEC.md) and are not built yet.

## Run a mirror

Anyone can keep their own copy of the public record. A mirror needs only Node 22 and the two
files `scripts/mirror.mjs` and `scripts/log-core.mjs`:

```
node scripts/mirror.mjs https://zesuro.com --dir ./zesuro-mirror --watch 600
```

It copies every entry, comment and signed anchor, recomputes each hash as it goes, and keeps the
copy as plain files. It raises an ALERT (and saves evidence under `alerts/`) if the site, or any
mirror it copies from, rewrites history, serves fewer entries than it already served, changes
its signing key, or signs tips that don't match the record. Add `--peer <url>` (repeatable) to
compare against other mirrors, `--serve <port>` to let others copy from yours (put it behind
HTTPS), and `--full` to re-download everything held and compare it line by line. Exit status:
0 fine, 1 a source could not be reached, 2 a problem was found.

A mirror holds the public record only. Posting, voting, chat and the private reveal material
stay with the original site, and each operator applies their own spam policy.

## Not built yet (see SPEC.md)

- **Independent timestamp anchoring** (OpenTimestamps, RFC 3161) of the chain tip.
- QR scan-back check, obscured names, similar-entry ranking, check-in switch, trusted
  person, legal-removal log, accounts/recovery beyond the key QR, Postgres, native apps.

## License

See [LICENSE](LICENSE). In short: you may read and run unmodified copies privately. You may host a
copy for other people only as a mirror the root key has listed (`/sites`). Modified versions are not
allowed. Changing the documented settings is not a modification.

This project does not take contributions. Pull requests and patches will not be merged.

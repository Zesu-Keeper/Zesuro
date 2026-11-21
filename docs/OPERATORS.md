# A group of independent operators

Status: a design, not a working system. It needs real partners, and nothing here should be presented as running.

## The problem

Today one person holds the root key and one server writes the record. That person can sign a false release, appoint a bad server or sign a false list of mirrors. Mirrors and the signed release log make cheating visible, but they do not stop it. A small group of independent operators would make cheating need several people to agree.

## What the operators would do

- **Run mirrors.** Each operator keeps a full copy of the record, checks every hash, and countersigns the site's signed checkpoints (anchors). This already works: `scripts/mirror.mjs` with `--witness`, and the site accepts a mirror's key with `scripts/admin.mjs witness-add`.
- **Watch the release log.** Each operator's mirror already checks that the append-only release log never changes or loses an entry, and raises an alert if it does.
- **Co-sign releases and the mirror list.** A release or a new mirror list would count only if enough operators had signed it as well as the root key.
- **Hold shares of the root key.** Later, the root key could be split so that a set number of operators (for example 3 of 5) must act together to appoint a new server or recover after a failure.

## What exists today

- Root-signed delegations, releases and mirror lists, each with its own signing purpose so a signature for one cannot be reused for another.
- A signed list of mirrors with a serial number that only rises, so an old list cannot be replayed.
- Witness countersignatures on anchors, stored by the site and checked by mirrors.
- A hash-linked release log checked by `code-check` and by mirrors.

## What would have to be built

1. **A threshold rule for releases.** Extend the release signature to be valid only with the root signature plus k operator signatures. `code-check` and the deploy script would check the extra signatures. The operators' public keys would be listed in a root-signed file.
2. **A threshold rule for the mirror list and delegations.** The same idea for `sites.json` and `authority.json`.
3. **Splitting the root key.** The root key is a hybrid of Ed25519 and SLH-DSA. Splitting it needs a threshold scheme for each part, and there is no mature threshold version of SLH-DSA. A simpler route is a list of several independent root keys, any k of which must sign. That avoids splitting anything and is the recommended first step.
4. **A way to add and remove operators**, itself needing k signatures, with a published waiting period.
5. **A key ceremony** for each operator: a key made on a machine they control, a public key sent through a second channel, and an offline backup.

## Choosing operators

- Different people, different hosting companies and, ideally, different countries.
- Not employed by the same organisation, and not a single legal entity.
- Each must be able to run a small server, keep an offline key, and answer an alert within a day.
- Publish who they are, or at least a stable public identity. A hidden operator cannot be held to account.

## Risks

- More operators means more keys that can be lost or stolen. Every key needs an offline backup and a written recovery plan.
- If too many operators disappear, nobody can sign a release. The threshold has to leave room for losing some.
- Operators who only copy the record protect against rewriting. They do not protect against a bad release unless they also check the code the site serves.

## Smallest useful step

Find three people who will each run a mirror with `--witness` for a month. Record how often they raise alerts and how long they take to respond. Only then decide how to write the threshold rules.

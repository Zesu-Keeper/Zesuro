# WhenISaid - Product Spec

> Status: DRAFT v0.1 - captures decisions made in the founding conversation. Name chosen: **WhenISaid** (whenisaid.com; domain not yet registered). Repo visibility still to be confirmed.

## 1. One-line purpose

Say something now. It is permanently recorded with its exact time. You decide when your name is attached to it. Later, when someone asks "did you really say that?", the record answers.

## 2. Principles

1. **Permanence is the one feature that must be perfect.** Once sealed, an entry cannot be edited, deleted or backdated, by the author or by us.
2. **You own what you say.** No editorial moderation. Names and places are used at the author's own risk. (See section 10 for the legal-only removal policy.)
3. **As simple as a notes app.** Open, type, submit, choose when. No feed, likes, comments or scoring in the core flow.
4. **Text only.** No photos or faces anywhere in the product.
5. **Clearnet.** Standard website and mobile app. No dark-web hosting.

## 3. What is public and what is private

| Part of an entry | Visibility |
|---|---|
| Statement text | **Public immediately** at sealing (except any parts the author obscures, see section 7) |
| Sealed date and time | Public, exact, and independently timestamped |
| Author identity | **Hidden** until the author reveals, or until a locked/automatic reveal fires |
| Obscured names or places in the text | Hidden until reveal |

## 4. Entry statuses

- **Anonymous**: sealed; text and time are public; author not yet named.
- **Revealed**: author identity has been attached (and any obscured parts shown).
- **Unknown**: the author-set deadline passed without the author claiming the entry. It stays anonymous and appears in the "Unknown" list. The author can still reveal later.
## 5. Core flow (mobile and web)

1. App opens straight to a blank text box with the keyboard up. No setup required.
2. User types the statement.
3. User taps **Seal**. One sheet asks how/when to reveal (defaults pre-selected so it is one tap):
   - **I'll decide later** (default)
   - **On a date and time**
   - **No matter what** (locked, see section 6)
   - Optional deadline: after this date, move to Unknown if unclaimed
   - Optional: obscure parts of the text
4. A confirmation line states that sealing is final ("You can't edit or delete this").
5. The app shows "Sealed [date, time]" and returns to a blank box.
6. A second screen lists the user's entries, each with a **Reveal now** button.

## 6. Reveal types

### 6.1 "No matter what" (locked)
- The user sets a date and time. At that moment the author's identity (and any obscured text) is released automatically.
- **Nothing can stop it**: not the author, not us, not a lost phone or a forgotten login.
- Implementation: the identity and obscured parts are encrypted on the user's device with **time-lock encryption** (drand tlock) so they can only be opened at the chosen time. The release does not depend on our servers being online.
- One confirmation at sealing: "This can't be cancelled." No way back after that.
- No key backup is needed for this type, since the release is automatic.

### 6.2 "I'll decide later" (manual)
- The author releases whenever they choose by pressing **Reveal now**.
- This needs the author's secret key. To make sure the key survives:
  - **The user is required to save a QR code of the key before the entry is sealed.** The app shows the QR code and the user must save it (to photos/files, or print it).
  - The app asks the user to **scan the saved QR code back in** to prove it was saved and is readable. Sealing completes only after this check.
  - The QR code is a secret. Anyone holding it can claim the entry. The screen says so clearly.
  - If the key is lost, the entry can never be revealed by the author (unless a trusted person or check-in switch is set).
  - One key per device covers all manual entries, so after the first time the QR is only requested again if the key changes.

### 6.3 On a date (adjustable)
- The author sets a reveal date and can change or cancel it before it passes. Requires the key. If they want it unstoppable, they use 6.1.

### 6.4 Additional automatic and helper triggers
- **Deadline**: if unclaimed by the author-set date, the entry moves to Unknown (section 4).
- **Check-in switch**: if the author stops checking in for a set period, authorship is revealed automatically.
- **Trusted person**: the author names someone who can press Reveal on their behalf (for example if the author dies).
- **Event watch (post-v1, optional)**: an author-defined mechanical rule (for example a keyword on a named source). Clearly labelled as mechanical.

## 7. Obscured names and places

- The author can mark parts of the text as hidden, e.g. "██████ will be arrested in ██████."
- The **full original text is cryptographically committed at sealing time**, so it cannot be changed afterwards.
- The hidden parts are encrypted on the author's device; the platform never holds the real names.
- At reveal, the full text is shown and anyone can verify it matches the commitment made on the sealed date.
- If the author chooses to name people publicly in the visible text, that is their choice and risk.

## 8. Authorship and keys

- The app creates a secret key on the device at first use. The user does not manage it.
- Each entry is signed with that key at sealing. Only a fingerprint is stored, so entries cannot be publicly linked to a person or to each other.
- At reveal the author signs again to prove the same key made the entry.
- Backup: the mandatory QR code for manual entries (6.2). Optional later: email or passkey recovery.
- No account, email or profile is required to seal.

## 9. Timestamps and proof

- Sealed time is recorded to the second and shown in UTC with local time.
- Each entry's fingerprint is anchored to independent public timestamp services (OpenTimestamps/Bitcoin, plus an RFC 3161 timestamp authority) so the sealed time does not depend on trusting us.
- Each entry has a public page and a downloadable proof file that can be checked without our servers.
- This is proof of *when it was said*, not proof that it is *true*.

## 10. Public record, removals and legal posture

- The website shows a public record of entries: text, sealed time, status, and (once revealed) the author and reveal time.
- **No editorial moderation.** Nothing is removed for being false, offensive, rude or controversial. No community flagging, reviewers or scoring.
- **Legal-only removals.** An entry is hidden only when a court order or legal authority requires it.
- **Removals are logged publicly**: "Entry #N hidden by legal order, [date]." The entry's sealed timestamp stays in the record.
- Locked reveals cannot be cancelled by anyone. If a court orders an entry hidden, it is hidden from display and logged as above.
- Get a lawyer to review terms and Australian obligations (defamation, Online Safety Act) before launch.

## 11. Ranking similar statements

- Because text is public, similar statements can be grouped.
- Everyone who made a similar statement is acknowledged, ordered by sealed time (earliest first).
- Counter-predictions are not linked; an opposing view is simply its own thread.
- v1: exact and near-duplicate matching. Later: author-assisted linking.

## 12. Out of scope for v1

Truth scoring, likes/comments, photos, profiles with images, event-watch triggers, store-listed native apps (start with an installable web app/PWA).

## 13. Suggested technical approach (draft)

- Installable PWA (one codebase for web, phone and desktop); native wrappers later.
- Client-side crypto using the Web Crypto API; time-lock via drand tlock.
- Timestamp anchoring via OpenTimestamps and an RFC 3161 authority.
- Small backend: entries table, public feed, search/grouping of similar text, legal-removal log.
- Stack suggestion: TypeScript, Next.js, Postgres.

## 14. Open decisions

- [x] Product name: WhenISaid (chosen)
- [ ] Register whenisaid.com (also .org and .app, all open when checked) and run a trademark search (IP Australia, USPTO); check Instagram/Reddit/X handles by hand
- [ ] GitHub repo visibility (private recommended until launch)
- [ ] Optional account recovery beyond the QR code (email, passkey, recovery phrase)
- [ ] Retention: how long we promise to keep the record, and what happens if we shut down
- [ ] Legal review and terms of service
- [ ] Exact matching approach for similar statements

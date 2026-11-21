# Plan for steps 4 and 5

The plan lists these items without a written specification, so this note says what each one would mean, what it would cost, and what I recommend. Nothing in this note is built yet, except the document proofs from step 5, which are live.

## Step 4

**Drand rounds as a time witness (recommended).** At the moment someone posts, their browser would fetch the latest drand beacon through the site, check its signature against the pinned drand key, and include the round number and signature in the post. Anyone can then check that the post cannot have been made before that round, without trusting the site. Together with the mirrors' signed stamps, which give a latest-possible time, the post's time is boxed in from both sides. Cost: a new hash version (v6) that covers the beacon, changes to `log-core.mjs`, `verify-log`, mirrors, restore and the snapshot code, plus tests. About a day of careful work.

**Private exact time (recommended, same change).** Today the record shows the exact time a post appeared. A post could instead show only a coarse time (the hour or the day), with the exact time locked in a commitment the author opens when they reveal. This needs the same new hash version, so it should be built together with the item above. The default delay of one to six hours already blurs the time for most people.

**Moving mailboxes each round.** Private replies use twelve monthly keys sealed into the post. Rotating more often means more keys in every post: weekly keys would be about 170 KB per post, daily keys over a megabyte. A cheaper option is to keep monthly keys and let the author choose a shorter period for sensitive posts. Decision needed: how often should keys change, and is the extra size acceptable?

**Fixed-rate traffic (not recommended).** The browser would send same-size dummy requests at a steady rate so a network observer cannot tell when a real post or reply happens. It does not hide anything from the site itself, because real and dummy requests still arrive at different endpoints. It costs constant bandwidth and is easy to get subtly wrong. Tor Browser already does this job better. The shared inbox feed that every visitor fetches (the existing inbox cover) is the part worth keeping.

## Step 5

**Self-releasing deniability.** Private chat already authenticates messages with keys that both people hold, so neither person can prove to an outsider what the other said, and each message key is erased after use. The items that are signed, and so not deniable, are the source's introduction and the proofs that a post is theirs. Making those deniable after a delay would mean publishing the signing material through a time lock to a future drand round, so anyone could forge them from then on. That works, but it also weakens the proofs for the person they were meant to help. Decision needed: should an introduction be deniable, and should it become forgeable after a set time? Until that is answered, I do not recommend building it.

**Document existence proofs (done).** The document page makes a fingerprint of a file inside the browser, lets someone record it as a post, and lets anyone with the same file check whether it was recorded and when. Nothing is uploaded.

## What I need from you

1. Go ahead with the drand time witness and the private exact time together as hash version 6?
2. Mailbox key period: keep monthly, or offer weekly for sensitive posts?
3. Skip fixed-rate traffic?
4. Should chat introductions become deniable after a delay?

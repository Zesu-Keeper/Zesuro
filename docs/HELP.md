# Zesuro help

Zesuro is a place to say something and have it recorded with the exact time, in a way nobody can change later. You can stay anonymous, and you decide if and when your name is attached.

This page explains how to use it, how it keeps you safe, and how it is set up, in plain language. If you want the technical detail, there is a [technical guide](/help/technical) and the [source code](https://github.com/Zesu-Keeper/Zesuro).

## Using Zesuro

### What it is for

People use Zesuro to put a statement on record before something happens, or to say something without being identified. Everything you post is public and permanent. Your name is not shown unless you choose to show it.

### Posting a statement

Open **Say it** (the highlighted button at the top), write a title and your text, enter the name you want shown, choose when it will be shown, and press Seal. Nobody can edit or delete it afterwards, including the owner of the site.

### Staying safe while you post

- **A quick check first.** The page asks three questions: is this a work or shared device, is someone else running your network, and does anyone else look at this device. If any answer is yes, stop and use a personal device somewhere else.
- **Details that give you away.** As you type, the page lists names, dates, numbers, places and jobs it finds. Ask yourself how many people know each one. You can hide any of them until you reveal, with one tap.
- **Hidden marks.** Text copied from a work document can carry invisible characters or look-alike letters that trace it to one copy. The page spots these and can remove them. Wording can be tagged too, so put copied text in your own words.
- **A delay by default.** A post normally appears at a random time in the next 1 to 6 hours, and its recorded time is when it appears. That stops anyone matching the post to the moment you were online. You can turn the delay off when the exact time matters more. While it waits, the post is held on the site's server and the site could read it, so it is only safe from outsiders, not from whoever runs the server.
- **Leave quickly.** The button in the corner, or pressing Esc twice, swaps the page for an ordinary search page.

### Choosing when your name is shown

- **Decide later.** The post is anonymous. You show the name you entered yourself, any time, from My posts. Your browser keeps the name with your key.
- **On a date.** Your name appears automatically at the time you pick. Until then nobody can read it, not even the site.
- **No matter what.** Like a date, but it can never be stopped once you have sealed it.

Every post needs a name. A name is only a claim that the same key sealed the post. Anyone can type any name, so a shown name is only as believable as the person who showed it.

### Hiding parts of your text

Put words in double square brackets, like `[[this]]`, and the public sees a block instead. The hidden words open at the same moment your name does. The record keeps a fingerprint of them, so they cannot be changed in between.

### Your key

The first time you post, your browser makes a secret key. It is what proves later that you wrote your posts. There is no account and no password.

Back the key up when the site asks you to, and keep the backup somewhere private. Anyone who has it can prove they wrote your posts. If you lose it and have no backup, nobody can restore it for you.

If you would rather remember your key than save a file, you can use a six-word key instead. The site gives you six random words to write down, and those words make the same key on any device. Make one in a browser that has no key yet, on the [six-word key page](/phrase). Only use the words the site gives you, because words you choose yourself are much easier to guess. Anyone who has the six words can post and reveal as you.

### Using another device

Open Transfer on your old device to make a code and a bundle. Open Transfer on the new device and enter them. You can use the same steps to move to a new address of the site.

### Proving a document existed

You can show that you had a file at a certain time without showing anyone what is in it. On the [document page](/document), pick the file. Your browser makes a short fingerprint of it, and the file never leaves your device. If you post the fingerprint, the record keeps it with the time. Later, anyone who holds the exact same file can check it on the same page. Changing even one letter in the file gives a different fingerprint. Only record fingerprints of files you are happy to be linked to, because anyone with the same file can see that it was recorded.

### Reading and reacting

- Search the record by words or by date.
- Comment on a post. Comments are permanent too.
- Like or dislike a post, and vote on whether the thing described really happened. You get one vote per browser.
- Flag spam. A flag is a public count that moves a post down the list. Nothing is ever removed because of flags.
- The Came true page shows revealed posts ranked by how many people say they happened.

## Private replies

### Replying to a post

Under a post that allows it there is a **Reply privately** button. Your reply is locked so that only the real author of that post can read it. Nobody else can, including this site, and the author stays anonymous. If the author answers, you talk in a private chat that appears under Private chat in the same browser.

When you post, private replies are on unless you turn them off. Replies to your posts appear under **My posts**. Each month's replies use their own key, and your browser throws that key away when the month is over, so old replies can't be opened later.

### Is it really a journalist?

Anyone can claim to be a reporter, including the people you wrote about. A journalist can set up a **verified identity**: their newsroom publishes their key on its own website. Their replies then show "Verified: name at newsroom". Replies without that are folded away and marked "Not verified". Treat them with care, and don't share anything that identifies you until you are sure who you are talking to.

Journalists set this up on the [verified journalist page](/journalist).

## Private chat

### What it is for

Private chat lets someone talk to another person, for example a source and a reporter, without the site being able to read the messages. The reporter can check that the person they are talking to really wrote a particular public post, without learning who that person is.

### Starting a chat

1. Open Private chat and start a new chat. You get a link.
2. Send the link to the other person by a channel you trust. You choose whether it works once, a few times, or without limit.
3. When they open it, both browsers set up the encryption. Each side sees a short safety code.
4. Compare the safety code by voice or in person. If the codes match, nobody is in the middle.
5. Either of you can set messages to delete after a time, or delete the whole chat.

### Extra protection

- **Every message has its own key.** The key is erased as soon as the message has been used. If someone steals your device or a key later, they can't open messages that were already sent. This is called forward secrecy.
- **Keep a chat only for this tab.** When you start or join a chat you can choose "Only keep this chat until I close this tab". Nothing is saved on the device, and the chat is gone for you when the tab closes.
- **A passcode.** You can lock your chats with a passcode. Everything chat-related on the device is scrambled with it, and the chats lock again by themselves after a few quiet minutes. If you forget the passcode, nobody can open the chats.
- **One device only.** A chat stays on the device that started it. It can't be copied to another device, because that would weaken the protection.

### Ending a chat

Press "End chat and delete keys" inside a chat. Every message is removed from the site, and the key on your device is erased. The other person's key is erased as soon as their browser next checks the chat. After that, nobody can read it again. If you only want to forget the chat on your own device, press "Delete my key here". The other person can still read it. The Private chat page also has an erase button that ends every chat at once.

### Know the limits

Chat is text only. A message you have already read stays on your device until you delete the chat or the timer removes it, so anyone who can use your device while the chats are open can read it. The site can see that a chat exists and roughly when messages arrive. If you are in real danger, use Tor Browser and a device you trust.

## Is it safe?

### How your privacy is protected

- **No accounts and no tracking.** You never give an email address or a phone number, and the site does not record visitor addresses.
- **Your name stays locked.** For dated posts your browser locks your name until the time you chose. The lock is opened by a public timer run by independent organisations, not by the site.
- **Posts cannot be changed quietly.** Every post and comment is linked to the one before it. Changing anything would break the links after it.
- **Other people keep copies.** Independent sites called mirrors keep their own copy of the record and check it. A rewrite would not match their copies.
- **The code is public.** Anyone can read how the site works, and the site's scripts are signed so they can be checked.

### What can still go wrong

- **Your device.** Malware or a bad browser extension can read your key. Keep your devices clean.
- **What you write.** Details in the text can identify you: places, times, facts only a few people know. This is how most people are found.
- **Your network.** Your internet provider can see that you visited the site. Tor Browser hides that.
- **The site itself.** Your browser runs code that the site sends. If the site were taken over, it could send harmful code. Mirrors and the signed code check exist to catch this, but they only help if people use them.
- **The future.** Some of the encryption could be broken by a very large quantum computer one day.
- **No outside audit yet.** The cryptography has been tested against reference tools, but nobody independent has audited it.

### Simple safety tips

- Use Tor Browser if you could be harmed by being identified.
- Do not post from a work device or work network.
- Read your text once as if you were trying to find the writer.
- Keep your key backup offline.
- Do not tell anyone which posts are yours unless you choose to.

## How the site is set up

### Where it runs

The site runs on one server, a small rented computer in a data centre, run by its owner. Your connection to it is encrypted with HTTPS. There is also a Tor address for people who want extra privacy. The details are in the [technical guide](/help/technical).

### What the server keeps

It keeps the public posts and comments, the locked parts of dated posts, and chat messages it cannot read. It does not keep accounts, visitor addresses, or the names of locked posts.

### Who is in charge of the record

The owner holds a master key, kept off the server. Only the server that key has approved can add posts. If that server is lost, the owner can approve another one and the record carries on from the copies that mirrors hold. Nobody else can make a server count.

### Mirrors

A mirror is another site that keeps a copy of the record and checks it. The [Mirrors page](/sites) lists the ones the owner has approved. The [Anchors page](/anchors) shows the signed checkpoints that mirrors countersign.

### Checking it yourself

You do not have to take our word for any of this. People who are comfortable with a command line can run the checks in the [technical guide](/help/technical). Everyone else can rely on the mirrors that others run.

## Questions

### Can the site owner see who I am?

Not from the record. For posts that reveal on a date, the name is locked before it leaves your browser. For posts you reveal yourself, the name never leaves your browser until you choose. The owner does not log visitor addresses. The owner still runs the code your browser downloads, which is why the checks above matter.

### Can a post be removed?

No. Posts are permanent, and spam is only flagged. There is no removal process yet.

### I lost my key

There is no recovery. Nobody, including the owner, can prove you wrote your posts without it. Posts you made stay on the record.

### My reveal did not happen

The public timer may not have reached your time yet, or the site could not reach it. It tries again later. If it still does not open, ask for help through the project page.

### A post was refused as too fast

The site limits how often posts can be sent. Wait a little and try again.

### Can I run my own copy?

You can run a private copy to read and check the record. To host a copy for other people, the owner has to list it as a mirror, and the software must be unmodified. The [license](https://github.com/Zesu-Keeper/Zesuro/blob/main/LICENSE) has the exact terms.

## Go deeper

### Guides

- [Technical guide](/help/technical): checking the record, running a mirror, hosting a server
- [Source code](https://github.com/Zesu-Keeper/Zesuro)
- [Specification](https://github.com/Zesu-Keeper/Zesuro/blob/main/SPEC.md)
- [Operator runbook](https://github.com/Zesu-Keeper/Zesuro/blob/main/deploy/RUNBOOK.md)

### On this site

- [Mirrors](/sites)
- [Anchors](/anchors)
- [Record check](/api/chain)

### Outside resources

- [Tor Browser](https://www.torproject.org/download/), for hiding your visit from your internet provider
- [drand](https://drand.love), the public timer used to lock names until their date

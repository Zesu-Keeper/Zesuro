# Zesuro private chat add-on

The add-on carries its own copy of the private chat. Its code comes from the add-on package, not from the website, so a
seized or compelled server cannot send one person a changed version of the chat. The website still relays scrambled
messages; it never sees keys or text.

## Build

    npm run build:extension            # or: node scripts/build-extension.mjs --site https://zesuro.com

This writes `extension/dist/chrome/`, `extension/dist/firefox/`, a zip of each, and `HASHES.txt` with the SHA-256 of
every file. The build is reproducible: anyone can build the same commit and compare the hashes.

## Try it

- Chrome or Edge: open `chrome://extensions`, turn on Developer mode, choose "Load unpacked" and pick `extension/dist/chrome`.
- Firefox: open `about:debugging#/runtime/this-firefox`, choose "Load Temporary Add-on" and pick `extension/dist/firefox/manifest.json`.

Click the add-on's button to open the chat. Chat links opened on the website are handed straight to the add-on.

## Publish

Upload the zips to the Chrome Web Store and to Firefox Add-ons (addons.mozilla.org) under the project's own developer
accounts. Publish the `HASHES.txt` of each released version in the project, so people can check that what the stores
serve is what this commit builds.

## Limits

- Proving that you wrote a public post is not available in the add-on, because your post keys stay on the website.
- The add-on's own updates come through the browser's store. A store, or a stolen developer account, is now the thing to
  protect: use a hardware key on those accounts.

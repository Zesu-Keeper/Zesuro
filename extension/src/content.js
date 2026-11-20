// On the website's chat page: if the address carries a chat link, hand it to the add-on before the website's own
// code can do anything with it, and leave the website page.
(() => {
  const h = location.hash;
  if (!/^#(i=[A-Za-z0-9_-]{43}|r=[0-9a-f-]{36})$/.test(h)) return;
  // Take the secret out of this page straight away.
  history.replaceState(null, "", location.pathname);
  const api = globalThis.browser ?? globalThis.chrome;
  api.runtime.sendMessage({ hash: h });
})();

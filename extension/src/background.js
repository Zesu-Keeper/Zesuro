// Opens the add-on's own chat page: from the toolbar button, or when a chat link is opened on the website.
const api = globalThis.browser ?? globalThis.chrome;
const page = (hash = "") => api.runtime.getURL("chat.html") + hash;

api.action.onClicked.addListener(() => api.tabs.create({ url: page() }));

api.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || typeof msg.hash !== "string" || !sender.tab) return;
  // Only a chat link fragment, nothing else, is carried across.
  if (!/^#(i=[A-Za-z0-9_-]{43}|r=[0-9a-f-]{36})$/.test(msg.hash)) return;
  api.tabs.update(sender.tab.id, { url: page(msg.hash) });
});

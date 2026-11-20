// The chat, running from inside the browser add-on. The add-on carries this code itself, so the website can't
// change it: a seized or compelled server could send a different program to a visitor of the website, but not
// to someone who opens the chat from here.
import { createRoot } from "react-dom/client";
import ChatApp from "@/components/ChatApp";

declare const SITE: string;
globalThis.__ZESURO_SITE__ = SITE;

createRoot(document.getElementById("app")!).render(<ChatApp />);

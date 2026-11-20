import type { Metadata } from "next";
import { headers } from "next/headers";
import ChatApp from "@/components/ChatApp";
import { chatApexes, hostKind } from "@/lib/chat-hosts";

export const dynamic = "force-dynamic";

export async function generateMetadata(): Promise<Metadata> {
  // On a private chat address nothing says what site this is.
  if (hostKind((await headers()).get("host")) === "chat")
    return { title: "Notes", description: "", robots: { index: false, follow: false } };
  return {
    title: "Private chat · Zesuro",
    description: "A private conversation between two people. The site stores it but cannot read it.",
    robots: { index: false },
  };
}

export default async function ChatPage() {
  const onChatHost = hostKind((await headers()).get("host")) === "chat";
  return <ChatApp apexes={onChatHost ? [] : chatApexes()} onChatHost={onChatHost} />;
}

import type { Metadata } from "next";
import { headers } from "next/headers";
import ChatApp from "@/components/ChatApp";
import { chatApexes, isChatRequest } from "@/lib/chat-hosts";
import { onionAddress, viaTor } from "@/lib/tor";

export const dynamic = "force-dynamic";

export async function generateMetadata(): Promise<Metadata> {
  // On a private chat address nothing says what site this is.
  if (isChatRequest(await headers()))
    return { title: "Notes", description: "", robots: { index: false, follow: false } };
  return {
    title: "Private chat · Zesuro",
    description: "A private conversation between two people. The site stores it but cannot read it.",
    robots: { index: false },
  };
}

export default async function ChatPage() {
  const h = await headers();
  const onChatHost = isChatRequest(h);
  return (
    <ChatApp
      apexes={onChatHost ? [] : chatApexes()}
      onChatHost={onChatHost}
      tor={onChatHost ? null : { via: viaTor(h), onion: onionAddress() }}
    />
  );
}

import { headers } from "next/headers";
import type { Metadata } from "next";
import ChatApp from "@/components/ChatApp";
import RecordView, { type RecordParams } from "@/components/RecordView";
import { isChatRequest } from "@/lib/chat-hosts";

export const dynamic = "force-dynamic";

// On a private chat address the plain "/" is the chat itself, and nothing says what site this is.
export async function generateMetadata(): Promise<Metadata> {
  if (isChatRequest(await headers())) return { title: "Notes", description: "", robots: { index: false, follow: false } };
  return { title: "Popular posts · Zesuro" };
}

export default async function Home({ searchParams }: { searchParams: Promise<RecordParams> }) {
  if (isChatRequest(await headers())) return <ChatApp apexes={[]} onChatHost />;
  return <RecordView sp={await searchParams} sort="top" />;
}

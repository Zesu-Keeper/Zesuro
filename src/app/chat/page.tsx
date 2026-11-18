import type { Metadata } from "next";
import ChatApp from "@/components/ChatApp";

export const metadata: Metadata = {
  title: "Private chat · Zesuro",
  description: "An encrypted conversation between two people. The site stores it but cannot read it.",
  robots: { index: false },
};

export default function ChatPage() {
  return <ChatApp />;
}

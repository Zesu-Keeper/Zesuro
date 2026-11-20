import type { Metadata } from "next";
import { headers } from "next/headers";
import SayForm from "@/components/SayForm";
import { onionAddress, viaTor } from "@/lib/tor";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Say it · Zesuro" };

export default async function SayPage() {
  const h = await headers();
  return <SayForm viaTor={viaTor(h)} onion={onionAddress()} />;
}

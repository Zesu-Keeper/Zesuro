import type { Metadata } from "next";
import JournalistSetup from "@/components/JournalistSetup";

export const metadata: Metadata = { title: "Verified journalist identity · Zesuro" };

export default function JournalistPage() {
  return <JournalistSetup />;
}

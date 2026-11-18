import type { Metadata } from "next";
import DocView from "@/components/DocView";

export const dynamic = "force-dynamic";
export const metadata: Metadata = {
  title: "Help · Zesuro",
  description: "How to use Zesuro, how it keeps you safe, and how the site is set up.",
};

export default function HelpPage() {
  return (
    <DocView
      file="HELP.md"
      groups={[
        { name: "Using Zesuro", sections: ["Using Zesuro", "Private chat", "Questions"] },
        { name: "Safety and trust", sections: ["Is it safe?", "How the site is set up"] },
      ]}
      start={[
        { href: "#using-zesuro", title: "Post something", text: "Seal a statement and choose when your name appears." },
        { href: "#is-it-safe", title: "Is it safe?", text: "What protects you, and what does not, in plain words." },
        { href: "#how-the-site-is-set-up", title: "How it is set up", text: "Where it runs and who is in charge of the record." },
      ]}
    />
  );
}

import type { Metadata } from "next";
import DocView from "@/components/DocView";

export const dynamic = "force-dynamic";
export const metadata: Metadata = {
  title: "Technical guide · Zesuro",
  description: "Checking the record, running a mirror, hosting a server and how the cryptography fits together.",
};

export default function TechnicalPage() {
  return (
    <DocView
      file="TECHNICAL.md"
      groups={[
        { name: "Checking", sections: ["Verifying the record"] },
        { name: "Operating", sections: ["Hosting your own server", "Keeping the record alive", "Troubleshooting"] },
        { name: "Design", sections: ["How the cryptography fits together", "Known limits"] },
      ]}
      start={[
        { href: "#verifying-the-record", title: "Check the record", text: "Verify the log, the code and the signed lists yourself." },
        { href: "#hosting-your-own-server", title: "Host a server", text: "Install, secure and run a copy." },
        { href: "#keeping-the-record-alive", title: "Keep it alive", text: "Root key, mirrors, snapshots and recovery." },
      ]}
    />
  );
}

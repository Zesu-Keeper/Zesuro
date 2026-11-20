import fs from "node:fs";
import path from "node:path";
import type { Metadata } from "next";
import Stamp from "@/components/Stamp";

export const dynamic = "force-dynamic";
export const metadata: Metadata = {
  title: "Mirrors · Zesuro",
  description: "Other sites that keep a copy of the Zesuro record, and sites the owner says are not connected to it.",
};

type Mirror = { url: string; name: string; key?: string; note?: string; at: number };
type Bad = { url?: string; key?: string; reason: string; at: number };
type Manifest = { serial: number; at: number; mirrors: Mirror[]; malicious: Bad[] };

function rootKey(): string | null {
  try {
    const a = JSON.parse(fs.readFileSync(path.join(process.cwd(), "data", "authority.json"), "utf8")) as { root?: unknown };
    return typeof a.root === "string" && a.root.length < 400 ? a.root : null;
  } catch {
    return null;
  }
}

function load(): { m: Manifest | null } {
  try {
    const f = JSON.parse(fs.readFileSync(path.join(process.cwd(), "data", "sites.json"), "utf8")) as { manifest: string };
    const m = JSON.parse(f.manifest) as Manifest;
    if (!Array.isArray(m.mirrors) || !Array.isArray(m.malicious)) return { m: null };
    return { m };
  } catch {
    return { m: null };
  }
}

export default function SitesPage() {
  const { m } = load();
  const root = rootKey();
  return (
    <main>
      <h1>Mirrors</h1>
      <p className="lede">
        A mirror is another website that keeps its own copy of the Zesuro record. If this site ever changed
        something, the copies would no longer match. You do not need to do anything with this page to use Zesuro.
      </p>
      {!m ? <p className="empty">No mirrors have been listed yet.</p> : null}
      {m ? (
        <>
          <h2>Approved mirrors ({m.mirrors.length})</h2>
          <p className="meta">Sites the owner has approved as keeping a faithful copy.</p>
          {m.mirrors.length === 0 ? <p className="empty">None yet.</p> : null}
          {m.mirrors.map((s) => (
            <div className="card" key={s.url}>
              <strong>{s.name}</strong> <span className="mono">{s.url}</span>
              {s.note ? <p>{s.note}</p> : null}
            </div>
          ))}
          {m.malicious.length > 0 ? (
            <>
              <h2>Not connected to Zesuro ({m.malicious.length})</h2>
              <p className="meta">Sites the owner says are not Zesuro and are not approved. Be careful with them.</p>
              {m.malicious.map((s, i) => (
                <div className="card" key={`${s.url ?? ""}${s.key ?? ""}${i}`}>
                  {s.url ? <span className="mono">{s.url}</span> : <em>A signing key, with no website</em>}
                  <p>{s.reason}</p>
                </div>
              ))}
            </>
          ) : null}
          <p className="meta">
            List {m.serial}, updated <Stamp ms={m.at} />
          </p>
        </>
      ) : null}
      <details className="card">
        <summary>For people who want to check this list</summary>
        <p className="meta">
          The lists are signed with the owner&apos;s key, so they cannot be altered without it being noticed. This page
          only shows them. To check the signature yourself, you need the owner&apos;s public key from somewhere other than
          this site, then run{" "}
          <span className="mono">node scripts/sites.mjs verify --file sites.json --root &lt;key&gt;</span> on the file at{" "}
          <a href="/api/sites">/api/sites</a>. Most people can skip this.
        </p>
        {root ? (
          <p className="meta">
            The key this site gives: <span className="mono" style={{ wordBreak: "break-all" }}>{root}</span>
            <br />
            Compare it with a copy from another place before relying on it.
          </p>
        ) : null}
      </details>
    </main>
  );
}

import fs from "node:fs";
import path from "node:path";
import type { Metadata } from "next";
import Stamp from "@/components/Stamp";

export const dynamic = "force-dynamic";
export const metadata: Metadata = {
  title: "Mirrors and impostors · Zesuro",
  description: "Sites the root key vouches for as mirrors, and sites it names as impostors.",
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
      <h1>Mirrors and impostors</h1>
      <p className="lede">
        The holder of the root key keeps two lists and signs them. <strong>Mirrors</strong> are sites the root
        vouches for as keeping a faithful copy of this record. <strong>Impostors</strong> are sites or keys that
        are not part of it: they must not be trusted to sign, publish or vouch for anything here.
      </p>
      <p className="meta">
        This page only displays the lists. Do not trust it: check the signed file against the root public key you got
        from someone other than this site, with{" "}
        <span className="mono">node scripts/sites.mjs verify --file sites.json --root &lt;root key&gt;</span>. The file is at{" "}
        <a href="/api/sites">/api/sites</a>.
      </p>
      {root ? (
        <p className="meta">
          Root public key, as this site states it: <span className="mono" style={{ wordBreak: "break-all" }}>{root}</span>
          <br />
          Do not take this on this site&apos;s word. Compare it with copies from other places before you pin it.
        </p>
      ) : null}
      {!m ? <p className="empty">No list has been signed yet.</p> : null}
      {m ? (
        <>
          <p className="meta">
            List {m.serial}, signed <Stamp ms={m.at} />
          </p>
          <h2>Mirrors ({m.mirrors.length})</h2>
          {m.mirrors.length === 0 ? <p className="empty">None listed.</p> : null}
          {m.mirrors.map((s) => (
            <div className="card" key={s.url}>
              <strong>{s.name}</strong> <span className="mono">{s.url}</span>
              {s.key ? <div className="meta mono">key {s.key.slice(0, 40)}…</div> : null}
              {s.note ? <p>{s.note}</p> : null}
            </div>
          ))}
          <h2>Impostors: not signed by the root, do not trust ({m.malicious.length})</h2>
          {m.malicious.length === 0 ? <p className="empty">None listed.</p> : null}
          {m.malicious.map((s, i) => (
            <div className="card" key={`${s.url ?? ""}${s.key ?? ""}${i}`}>
              {s.url ? <span className="mono">{s.url}</span> : <em>key only</em>}
              {s.key ? <div className="meta mono">key {s.key.slice(0, 40)}…</div> : null}
              <p>{s.reason}</p>
            </div>
          ))}
        </>
      ) : null}
    </main>
  );
}

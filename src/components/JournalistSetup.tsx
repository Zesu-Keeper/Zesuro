"use client";

import { useEffect, useState } from "react";
import { createJournalist, DOMAIN, forgetJournalist, listingFor, loadJournalist, newsroomLists, type JournalistId } from "@/lib/journalist";

/**
 * A journalist sets up an identity once. Their newsroom publishes the public key on its own website, so a source can
 * see "Verified: Jane Doe at example.org" instead of having to take a stranger's word for it.
 */
export default function JournalistSetup() {
  const [id, setId] = useState<JournalistId | null>(null);
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [check, setCheck] = useState<"" | "checking" | "listed" | "missing">("");
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => setId(loadJournalist()), []);

  async function make() {
    setErr(null);
    const d = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!name.trim()) return setErr("Add your name as your newsroom would list it.");
    if (!DOMAIN.test(d)) return setErr("Enter your newsroom's web address, like example.org.");
    setId(await createJournalist(name, d));
  }

  async function verify() {
    if (!id) return;
    setCheck("checking");
    setCheck((await newsroomLists(id.domain, id.key, id.name)) ? "listed" : "missing");
  }

  return (
    <main>
      <h1>Verified journalist identity</h1>
      <p className="lede">
        Sources on Zesuro are anonymous, and anyone can claim to be a reporter. Including the people a source wrote
        about. A verified identity lets a source see that your reply really comes from a journalist at your newsroom.
      </p>
      {!id ? (
        <div className="card">
          <label className="lbl" htmlFor="j-name">Your name, as your newsroom lists you</label>
          <input id="j-name" type="text" maxLength={80} value={name} onChange={(e) => setName(e.target.value)} />
          <label className="lbl" htmlFor="j-domain">Your newsroom&apos;s web address</label>
          <input id="j-domain" type="text" placeholder="example.org" value={domain} onChange={(e) => setDomain(e.target.value)} />
          {err ? <p className="err">{err}</p> : null}
          <div className="row" style={{ justifyContent: "flex-start" }}>
            <button type="button" className="primary" onClick={make}>Make my identity</button>
          </div>
          <p className="count">
            The key is made and kept in this browser. Use a work device that your newsroom&apos;s security team looks after,
            not a personal phone.
          </p>
        </div>
      ) : (
        <div className="card">
          <p>
            <b>{id.name}</b> at <b>{id.domain}</b>
          </p>
          <p className="count">
            Ask your newsroom&apos;s web or security team to publish this file at{" "}
            <span className="mono">https://{id.domain}/.well-known/zesuro-journalists.json</span> (or add your entry to it):
          </p>
          <textarea className="plain mono" readOnly rows={6} value={listingFor(id)} onFocus={(e) => e.currentTarget.select()} />
          <div className="row" style={{ justifyContent: "flex-start" }}>
            <button type="button" onClick={verify} disabled={check === "checking"}>
              {check === "checking" ? "Checking…" : "Check that my newsroom lists me"}
            </button>
          </div>
          {check === "listed" ? <p className="notice">Your newsroom lists this key. Your private replies will show as verified.</p> : null}
          {check === "missing" ? <p className="err">Not listed yet. Replies you send will show as not verified until it is.</p> : null}
          <p className="count">
            When you reply privately to a post, you can sign the reply with this identity. Never reuse it on a personal device.
          </p>
          <button
            type="button"
            className="link"
            onClick={() => {
              if (window.confirm("Delete this identity from this browser? You'll need a new key listed by your newsroom.")) {
                forgetJournalist();
                setId(null);
              }
            }}
          >
            Delete this identity
          </button>
        </div>
      )}
    </main>
  );
}

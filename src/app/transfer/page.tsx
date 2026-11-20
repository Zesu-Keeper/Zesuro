"use client";

import { useState } from "react";
import { TRANSFER_KEYS, makeCode, openBundle, planImport, sealBundle, type ImportPlan } from "@/lib/transfer";

function readAll(): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const k of TRANSFER_KEYS) {
    try {
      out[k] = localStorage.getItem(k);
    } catch {
      out[k] = null;
    }
  }
  return out;
}

export default function Transfer() {
  const [code, setCode] = useState<string | null>(null);
  const [bundle, setBundle] = useState("");
  const [inText, setInText] = useState("");
  const [inCode, setInCode] = useState("");
  const [plan, setPlan] = useState<{ p: ImportPlan; items: Record<string, string> } | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function makeBundle() {
    setErr(null);
    setMsg(null);
    try {
      const have: Record<string, string> = {};
      for (const [k, v] of Object.entries(readAll())) if (v !== null) have[k] = v;
      if (!Object.keys(have).length) {
        setErr("This browser holds no Zesuro keys, so there is nothing to move.");
        return;
      }
      const c = makeCode();
      setBundle(await sealBundle(have, c));
      setCode(c);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not make the bundle");
    }
  }

  function download() {
    const url = URL.createObjectURL(new Blob([bundle], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "zesuro-keys.txt";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  async function check() {
    setErr(null);
    setMsg(null);
    setPlan(null);
    try {
      const items = await openBundle(inText, inCode);
      setPlan({ p: planImport(readAll(), items), items });
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not open the bundle");
    }
  }

  function apply() {
    if (!plan || plan.p.deviceKeyConflict) return;
    try {
      for (const k of plan.p.add) localStorage.setItem(k, plan.items[k]);
      setMsg(`Added ${plan.p.add.length} item(s) to this browser. Nothing that was already here was changed.`);
      setPlan(null);
      setInText("");
      setInCode("");
    } catch {
      setErr("This browser would not let the keys be saved.");
    }
  }

  return (
    <div>
      <h1>Move your keys</h1>
      <p className="lede">
        Your keys are kept in this browser, and only work on this website address. If you use Zesuro at a different address, it starts empty: your posts won&apos;t show up under My posts and your chats
        won&apos;t open. This page lets you carry your keys across yourself. Nothing is sent to any server.
      </p>

      <div className="card">
        <h2>1. On the browser that has your keys</h2>
        <p className="meta">
          This makes a locked bundle of everything this browser holds for Zesuro, plus a separate code that unlocks it. Send the two by different routes. Anyone who gets both can
          post, reveal and read chats as you.
        </p>
        <button className="primary" onClick={makeBundle}>
          Make a bundle and code
        </button>
        {code && (
          <div className="warnbox">
            <p className="lbl">Code (write it down, then close this page)</p>
            <p className="mono">{code}</p>
            <p className="lbl">Bundle</p>
            <textarea readOnly rows={4} value={bundle} onFocus={(e) => e.currentTarget.select()} />
            <div className="row">
              <button onClick={download}>Download bundle</button>
              <button
                onClick={() => {
                  setCode(null);
                  setBundle("");
                }}
              >
                Clear from this page
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <h2>2. On the other address</h2>
        <p className="meta">Open this same page there, paste the bundle and type the code. Keys that are already in that browser are never replaced.</p>
        <textarea rows={4} placeholder="Bundle (starts ZT1.)" value={inText} onChange={(e) => setInText(e.target.value)} />
        <input placeholder="Code" value={inCode} onChange={(e) => setInCode(e.target.value)} autoComplete="off" spellCheck={false} />
        <button className="primary" onClick={check} disabled={!inText.trim() || !inCode.trim()}>
          Check the bundle
        </button>
        {plan && (
          <div className="warnbox">
            <p>
              Would add <b>{plan.p.add.length}</b>. Already here: <b>{plan.p.same.length}</b>. Different here, so left alone: <b>{plan.p.keep.length}</b>.
            </p>
            {plan.p.deviceKeyConflict ? (
              <p>
                This browser already has its own key, so the import was stopped. Replacing it would cut you off from what you posted here. Use a browser that has no
                Zesuro keys yet, or move this browser&apos;s keys the other way.
              </p>
            ) : (
              <button className="primary" onClick={apply} disabled={!plan.p.add.length}>
                Add them to this browser
              </button>
            )}
          </div>
        )}
      </div>

      {msg && <p className="meta">{msg}</p>}
      {err && <p className="err">{err}</p>}
    </div>
  );
}

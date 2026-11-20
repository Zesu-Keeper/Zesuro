// Checking the release log (src/lib/release-log.ts) from outside: used by code-check.mjs and mirror.mjs.
import { createHash } from "node:crypto";
import { verify as hybridVerify } from "./hybrid-sig.mjs";

const ZERO = "0".repeat(64);
const sha = (s) => createHash("sha256").update(s).digest("hex");
export const logHash = (prev, seq, at, s) => sha(prev + "\n" + JSON.stringify(["zesuro-release-log-v1", seq, at, s]));

/** Problems with a full log (oldest first). Empty means: hash-linked from the start, every entry signed by `root`. */
export function logProblems(releases, root) {
  const out = [];
  let prev = ZERO;
  releases.forEach((r, i) => {
    if (r.seq !== i + 1) out.push(`release log entry ${i + 1} is missing or out of order`);
    if (r.prev !== prev) out.push(`release log entry ${r.seq} does not follow the one before it`);
    if (sha(r.release) !== r.sha) out.push(`release log entry ${r.seq} does not match its own fingerprint`);
    if (logHash(r.prev, r.seq, r.at, r.sha) !== r.hash) out.push(`release log entry ${r.seq} has a wrong hash`);
    if (root) {
      let ok = false;
      try { const j = JSON.parse(r.release); ok = typeof j.manifest === "string" && hybridVerify(root, "release", j.manifest, j.sig); } catch { /* not JSON */ }
      if (!ok) out.push(`release log entry ${r.seq} is not signed by the root key`);
    }
    prev = r.hash;
  });
  return out;
}

/** Fetches the whole log from a site. */
export async function fetchLog(base, fetchImpl = fetch) {
  const all = [];
  for (let after = 0; ; ) {
    const r = await fetchImpl(`${base}/api/release/log?after=${after}`, { signal: AbortSignal.timeout(20_000) });
    if (!r.ok) throw new Error(`release log: HTTP ${r.status}`);
    const d = await r.json();
    all.push(...d.releases);
    if (!d.releases.length || all.length >= d.count) return { ...d, releases: all };
    after = all[all.length - 1].seq;
  }
}

/** Problems if `now` (a fresh copy) is not `before` (an older copy) with entries added at the end. */
export function appendOnlyProblems(before, now) {
  const out = [];
  for (let i = 0; i < before.length; i++) {
    const a = before[i], b = now[i];
    if (!b) { out.push(`release log entry ${a.seq} has disappeared`); break; }
    if (a.hash !== b.hash) { out.push(`release log entry ${a.seq} has been changed`); break; }
  }
  return out;
}

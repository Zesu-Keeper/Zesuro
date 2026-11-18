// The root-signed directory of sites: which sites are genuine mirrors, and which are known impostors.
// Pure checks, no I/O. Used by scripts/sites.mjs (signing), the /api/sites route and anyone verifying.
//
// A file is { manifest, sig }: `manifest` is a JSON string (exactly these bytes are signed and served),
// `sig` is the root's hybrid signature over it with purpose "sites".
//   manifest = { v:1, serial, at, mirrors:[{url,name,key?,note?,at}], malicious:[{url?,key?,reason,at}] }
// The serial only goes up. A checker that remembers the highest serial it has seen refuses an older
// list, so a stale copy can't be replayed to hide a newly listed impostor.
import { isHybridKey, verify } from "./hybrid-sig.mjs";
import { isWriterKey } from "./log-core.mjs";

const int = (n) => Number.isSafeInteger(n) && n >= 0;
export const MAX_MIRRORS = 200, MAX_MALICIOUS = 1000;

/** Canonical form of a site address: lowercase https origin only (no path, query, credentials or port 443). Null if unusable. */
export function normUrl(u) {
  try {
    const x = new URL(String(u).trim());
    if (x.protocol !== "https:" || x.username || x.password || x.search || x.hash || (x.pathname !== "/" && x.pathname !== "")) return null;
    return x.origin.toLowerCase();
  } catch { return null; }
}
const keyOk = (k) => typeof k === "string" && (isWriterKey(k) || isHybridKey(k));
const text = (s, max) => typeof s === "string" && s.length <= max && !/[\u0000-\u001f\u007f]/.test(s);

/** Null if `manifest` (parsed) is well formed and self-consistent, else what is wrong. */
export function manifestProblem(m) {
  if (!m || m.v !== 1 || !int(m.serial) || m.serial < 1 || !int(m.at)) return "not a sites list (v, serial, at)";
  if (!Array.isArray(m.mirrors) || !Array.isArray(m.malicious)) return "mirrors and malicious must be lists";
  if (m.mirrors.length > MAX_MIRRORS || m.malicious.length > MAX_MALICIOUS) return "too many entries";
  const urls = new Map(), keys = new Map();
  const note = (map, k, where) => { if (map.has(k)) return `${k.slice(0, 40)} appears in both or twice (${map.get(k)} and ${where})`; map.set(k, where); return null; };
  for (const [i, s] of m.mirrors.entries()) {
    if (normUrl(s?.url) !== s?.url) return `mirror ${i + 1}: url must be a plain https origin, lowercase`;
    if (!text(s.name, 80) || !s.name) return `mirror ${i + 1}: needs a name (80 characters at most)`;
    if (s.key !== undefined && !keyOk(s.key)) return `mirror ${i + 1}: key is not a valid key`;
    if (s.note !== undefined && !text(s.note, 300)) return `mirror ${i + 1}: note too long or has control characters`;
    if (!int(s.at)) return `mirror ${i + 1}: missing time`;
    const e = note(urls, s.url, `mirror ${i + 1}`) || (s.key ? note(keys, s.key, `mirror ${i + 1}`) : null);
    if (e) return e;
  }
  for (const [i, s] of m.malicious.entries()) {
    if (s?.url === undefined && s?.key === undefined) return `malicious ${i + 1}: needs a url or a key`;
    if (s.url !== undefined && normUrl(s.url) !== s.url) return `malicious ${i + 1}: url must be a plain https origin, lowercase`;
    if (s.key !== undefined && !keyOk(s.key)) return `malicious ${i + 1}: key is not a valid key`;
    if (!text(s.reason, 300) || !s.reason) return `malicious ${i + 1}: needs a reason (300 characters at most)`;
    if (!int(s.at)) return `malicious ${i + 1}: missing time`;
    // a site can't be both: a mirror's url or key listed as malicious is a contradiction
    const e = (s.url && note(urls, s.url, `malicious ${i + 1}`)) || (s.key && note(keys, s.key, `malicious ${i + 1}`));
    if (e) return e;
  }
  return null;
}

/** Null if `file` ({manifest, sig}) is signed by `root` and well formed (and not older than `minSerial`), else what is wrong. */
export function sitesProblem(file, root, minSerial = 0) {
  if (!isHybridKey(root)) return "no valid root key to check against";
  if (!file || typeof file.manifest !== "string" || file.manifest.length > 400_000) return "not a sites file";
  if (!verify(root, "sites", file.manifest, file.sig)) return "not signed by the root key (both signatures are required)";
  let m; try { m = JSON.parse(file.manifest); } catch { return "the signed text is not JSON"; }
  const bad = manifestProblem(m);
  if (bad) return bad;
  if (m.serial < minSerial) return `an older list (serial ${m.serial}) than one already seen (${minSerial})`;
  return null;
}

/** What a checker should make of a site: "mirror", "malicious" or "unknown". Call after sitesProblem() returned null. */
export function classify(manifest, { url, key } = {}) {
  const m = typeof manifest === "string" ? JSON.parse(manifest) : manifest;
  const u = url ? normUrl(url) : null;
  if (m.malicious.some((s) => (u && s.url === u) || (key && s.key === key))) return "malicious";
  if (m.mirrors.some((s) => (u && s.url === u) || (key && s.key === key))) return "mirror";
  return "unknown";
}

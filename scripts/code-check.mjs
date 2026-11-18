#!/usr/bin/env node
// Checks that the JavaScript and CSS a site serves is exactly what the root key signed off.
//   node scripts/code-check.mjs https://zesuro.com --root <root public key>
// Why: browsers keep people's keys, and the site serves the code that reads them. A compromised
// server could serve a page that copies those keys. This can't be prevented from the server's
// side, but it can be noticed: the root key signs a list of the hashes of every script and
// stylesheet in a release (scripts/release.mjs), and anyone can compare what the site serves.
// Limits, stated plainly: a server can serve different code to a targeted visitor than to this
// checker, and inline scripts (which carry per-request nonces) are not covered. Running this from
// several places, and from people who are not the operator, makes targeting harder, not impossible.
import { createHash } from "node:crypto";
import { verify as hybridVerify, isHybridKey } from "./hybrid-sig.mjs";

const PAGES = ["/", "/say", "/mine", "/chat", "/transfer"];
const ASSET = /(?:src|href)="(\/_next\/static\/[^"?#]+\.(?:js|css))(?:\?[^"#]*)?"/g;
const sha = (b) => createHash("sha256").update(b).digest("hex");

/** Returns { release, problems }. `problems` is empty when everything served is signed. */
export async function checkCode(base, root, { fetchImpl = fetch, pages = PAGES } = {}) {
  const problems = [];
  const get = async (p) => { const r = await fetchImpl(base + p, { signal: AbortSignal.timeout(20_000) }); if (!r.ok) throw new Error(`${p}: HTTP ${r.status}`); return r; };
  if (!isHybridKey(root)) return { release: null, problems: ["no valid root key to check against"] };
  let rel;
  try { rel = await (await get("/api/release")).json(); } catch (e) { return { release: null, problems: [`no signed release is published (${e.message})`] }; }
  if (typeof rel?.manifest !== "string" || !hybridVerify(root, "release", rel.manifest, rel.sig)) return { release: null, problems: ["the release list is not signed by the root key"] };
  let m;
  try { m = JSON.parse(rel.manifest); } catch { return { release: null, problems: ["the signed release list is not JSON"] }; }
  if (m?.v !== 1 || typeof m.files !== "object" || m.files === null) return { release: null, problems: ["the signed release list is malformed"] };

  const seen = new Set();
  for (const page of pages) {
    let html;
    try { html = await (await get(page)).text(); } catch (e) { problems.push(`could not fetch ${page}: ${e.message}`); continue; }
    for (const [, url] of html.matchAll(ASSET)) seen.add(url);
  }
  for (const url of [...seen].sort()) {
    const want = m.files[url];
    if (!want) { problems.push(`${url} is served but is not in the signed release`); continue; }
    let got;
    try { got = sha(Buffer.from(await (await get(url)).arrayBuffer())); } catch (e) { problems.push(`could not fetch ${url}: ${e.message}`); continue; }
    if (got !== want) problems.push(`${url} differs from the signed release (served ${got.slice(0, 16)}…, signed ${String(want).slice(0, 16)}…)`);
  }
  if (!seen.size) problems.push("the pages reference no scripts to check (was the page fetched correctly?)");
  return { release: m, problems, checked: seen.size };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const base = (process.argv[2] || "").replace(/\/+$/, ""), ri = process.argv.indexOf("--root"), root = ri >= 0 ? process.argv[ri + 1] : "";
  if (!/^https?:\/\//.test(base) || !root) { console.error("Usage: node scripts/code-check.mjs https://zesuro.com --root <root public key>"); process.exit(2); }
  const { problems, checked, release } = await checkCode(base, root);
  for (const p of problems) console.log("FAIL  " + p);
  console.log(problems.length ? `\n${problems.length} problem(s) found` : `\nAll ${checked} scripts and stylesheets served match the release signed by the root key${release?.commit ? ` (commit ${String(release.commit).slice(0, 12)})` : ""}.`);
  process.exit(problems.length ? 1 : 0);
}

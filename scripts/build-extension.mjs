#!/usr/bin/env node
// Builds the browser add-on that carries its own copy of the private chat.
//
//   node scripts/build-extension.mjs [--site https://zesuro.com]
//
// Writes extension/dist/chrome and extension/dist/firefox, a zip of each, and HASHES.txt with the SHA-256 of
// every file. The same commit always gives the same files, so anyone can rebuild it and compare.
import { build } from "esbuild";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const SITE = arg("--site", "https://zesuro.com").replace(/\/+$/, "");
if (!/^https:\/\/[a-z0-9.-]+$/.test(SITE)) throw new Error("--site must be a plain https origin");
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const version = (pkg.version || "0.1.0").replace(/[^0-9.]/g, "") || "0.1.0";
const host = new URL(SITE).host;

const out = path.join(root, "extension/dist");
fs.rmSync(out, { recursive: true, force: true });

const bundle = await build({
  entryPoints: [path.join(root, "extension/src/main.tsx")],
  bundle: true,
  write: false,
  format: "iife",
  platform: "browser",
  target: ["chrome120", "firefox128"],
  jsx: "automatic",
  minify: true,
  legalComments: "none",
  sourcemap: false,
  define: { SITE: JSON.stringify(SITE), "process.env.NODE_ENV": '"production"' },
  tsconfig: path.join(root, "tsconfig.json"),
  logLevel: "warning",
});

const manifest = (kind) => ({
  manifest_version: 3,
  name: "Zesuro private chat",
  version,
  description: "Private chat whose code comes with the add-on, so the website can't change it.",
  action: { default_title: "Open private chat" },
  permissions: [],
  host_permissions: [`${SITE}/*`],
  content_scripts: [{ matches: [`${SITE}/chat*`], js: ["content.js"], run_at: "document_start" }],
  background: kind === "chrome" ? { service_worker: "background.js" } : { scripts: ["background.js"] },
  content_security_policy: { extension_pages: `script-src 'self'; object-src 'none'; connect-src ${SITE}; base-uri 'none'; form-action 'none'` },
  ...(kind === "firefox" ? { browser_specific_settings: { gecko: { id: `chat@${host}`, strict_min_version: "128.0" } } } : {}),
});

const files = {
  "chat.js": bundle.outputFiles[0].contents,
  "chat.html": fs.readFileSync(path.join(root, "extension/chat.html")),
  "style.css": fs.readFileSync(path.join(root, "src/app/globals.css")),
  "background.js": fs.readFileSync(path.join(root, "extension/src/background.js")),
  "content.js": fs.readFileSync(path.join(root, "extension/src/content.js")),
};
const sha = (b) => createHash("sha256").update(b).digest("hex");
const lines = [];
for (const kind of ["chrome", "firefox"]) {
  const dir = path.join(out, kind);
  fs.mkdirSync(dir, { recursive: true });
  const all = { ...files, "manifest.json": JSON.stringify(manifest(kind), null, 2) + "\n" };
  for (const [name, data] of Object.entries(all)) {
    fs.writeFileSync(path.join(dir, name), data);
    lines.push(`${sha(data)}  ${kind}/${name}`);
  }
  // Fixed timestamps and order, so the zip is the same every time.
  for (const name of Object.keys(all)) fs.utimesSync(path.join(dir, name), new Date(0), new Date(0));
  const zip = path.join(out, `zesuro-chat-${kind}-${version}.zip`);
  execFileSync("zip", ["-X", "-q", "-D", zip, ...Object.keys(all).sort()], { cwd: dir });
  lines.push(`${sha(fs.readFileSync(zip))}  ${path.basename(zip)}`);
}
fs.writeFileSync(path.join(out, "HASHES.txt"), lines.join("\n") + "\n");
console.log(lines.join("\n"));

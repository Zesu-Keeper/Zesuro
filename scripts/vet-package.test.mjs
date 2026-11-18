// Offline tests for the package-vetting rules (no network, nothing installed).
import { assess, exitCodeFor, levenshtein, lookalikes, scanSource } from "./vet-package.mjs";

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) pass++; else { fail++; console.log("FAIL:", m); } };
const NOW = Date.parse("2026-11-16T00:00:00Z");
const good = { exists: true, created: "2022-01-01T00:00:00Z", versionTime: "2025-01-01T00:00:00Z", versionCount: 14, downloadsMonth: 50000, repository: "git+https://github.com/x/y.git",
  lifecycle: [], maintainers: ["a", "b"], integrityOk: true, scan: [], treeInstallScripts: [], nonStandardSources: [], lookalikes: [], github: { archived: false, headFound: true }, gitHead: "abc" };
const levels = (f) => assess({ ...good, ...f }, NOW).map((x) => x.level);

ok(levenshtein("kitten", "sitting") === 3 && levenshtein("a", "a") === 0 && levenshtein("", "abc") === 3, "levenshtein");
ok(exitCodeFor(assess(good, NOW)) === 0, "a healthy package has no flags");
ok(exitCodeFor(assess({ exists: false }, NOW)) === 2, "a package that does not exist is blocked");
ok(levels({ integrityOk: false }).includes("block"), "hash mismatch blocks");
ok(levels({ nonStandardSources: ["x <- git+ssh://evil"] }).includes("block"), "dependency from outside the registry blocks");
ok(levels({ created: "2026-11-10T00:00:00Z" }).includes("warn"), "a week-old package warns");
ok(levels({ versionTime: "2026-11-15T12:00:00Z" }).includes("warn"), "a release from yesterday warns");
ok(levels({ downloadsMonth: 12 }).includes("warn"), "few downloads warns");
ok(levels({ versionCount: 1 }).includes("warn"), "a single version warns");
ok(levels({ repository: null }).includes("warn"), "no repository warns");
ok(levels({ lifecycle: ["postinstall"] }).includes("warn"), "an install script warns");
ok(levels({ treeInstallScripts: ["esbuild"] }).includes("warn"), "an install script in the tree warns");
ok(levels({ github: { archived: true, headFound: true } }).includes("warn"), "archived repo warns");
ok(levels({ github: { archived: false, headFound: false } }).includes("warn"), "commit missing from repo warns");
ok(levels({ audit: { high: 1, critical: 0 } }).includes("warn"), "audit highs warn");
ok(levels({ scan: ["runs other programs"] }).includes("warn"), "risky source pattern warns");
ok(levels({ publisher: "someone-else" }).includes("warn"), "publisher no longer an owner warns");
ok(!levels({ publisher: "a" }).includes("warn"), "publisher who is still an owner is quiet");
ok(!levels({ publisher: "GitHub Actions" }).includes("warn"), "automated publishing from the repository is not a warning");
ok(levels({ versionTime: "2022-01-01T00:00:00Z" }).includes("info") && exitCodeFor(assess({ ...good, versionTime: "2022-01-01T00:00:00Z" }, NOW)) === 0, "an old release is only informational");

ok(scanSource("const x = require('child_process').execSync('id')").includes("runs other programs"), "scan: exec");
ok(scanSource("eval(atob(s))").includes("evaluates strings as code"), "scan: eval");
ok(scanSource("x = eval(atob(s))").includes("evaluates strings as code") && scanSource("run(); eval(code)").includes("evaluates strings as code") && scanSource("const f = new Function('return 1')").includes("evaluates strings as code"), "scan: real eval forms are caught");
ok(!scanSource("  eval(a, x, brp = false) {\n    return 1;\n  }").includes("evaluates strings as code"), "scan: a method named eval is not eval");
ok(!scanSource("  eval(a: P, x: T, brp = false): T {\n    return x;\n  }").includes("evaluates strings as code"), "scan: a typed method named eval is not eval");
ok(!scanSource("return Poly.monomial.eval(coeffs, x);").includes("evaluates strings as code"), "scan: calling a method named eval is not eval");
ok(!scanSource("// Same as eval(a, basis(x)), but faster\nconst y = 1;").includes("evaluates strings as code") && !scanSource("/**\n * uses eval(x) here\n */").includes("evaluates strings as code"), "scan: a comment line is not code");
ok(scanSource("fetch('http://x'); eval(p)").includes("evaluates strings as code"), "scan: code after a URL string is still scanned");
ok(scanSource("fetch(u,{headers:{a:process.env.NPM_TOKEN}})").includes("reads environment variables"), "scan: env");
ok(scanSource("const k = '" + "A".repeat(500) + "'").includes("long encoded blob"), "scan: blob");
ok(scanSource("export const add = (a, b) => a + b;").length === 0, "scan: plain code is quiet");

const known = ["lodash", "express", "react", "@noble/curves", "axios"];
ok(lookalikes("lodahs", known).length === 1, "lookalike: transposition");
ok(lookalikes("expres", known).length === 1, "lookalike: missing letter");
ok(lookalikes("react-ai", known).length === 1, "lookalike: decoration");
ok(lookalikes("@noble/curvs", known).length === 1, "lookalike: scoped");
ok(lookalikes("lodash", known).length === 0, "lookalike: the real name is not its own lookalike");
ok(lookalikes("tlock-js", known).length === 0, "lookalike: unrelated name is quiet");

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

// Tests for the help-page Markdown reader and a style check of docs/HELP.md.
// Run: node --no-warnings scripts/mini-md.test.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import { parse, inline } from "../src/lib/mini-md.ts";
let n = 0; const eq = (a, b, m) => { assert.deepEqual(a, b, m); n++; }; const ok = (c, m) => { assert.ok(c, m); n++; };
eq(inline("a `b` **c** d"), [{ t: "text", v: "a " }, { t: "code", v: "b" }, { t: "text", v: " " }, { t: "bold", v: "c" }, { t: "text", v: " d" }]);
eq(inline("<script>alert(1)</script>"), [{ t: "text", v: "<script>alert(1)</script>" }], "markup stays text");
const b = parse("# T\n\nline one\nline two\n\n## H\n\n- a\n- b\n\n1. x\n2. y\n\n```\ncode <b>\n```\n\n| A | B |\n| --- | --- |\n| 1 | 2 |\n");
eq(b.map((x) => x.k), ["h1", "p", "h2", "ul", "ol", "code", "table"]);
eq(b[1].inl[0].v, "line one line two"); eq(b[5].text, "code <b>"); eq(b[6].rows.length, 1);
const src = fs.readFileSync(new URL("../docs/HELP.md", import.meta.url), "utf8");
const all = parse(src); ok(all.length > 80, "the help file parses into many blocks");
ok(all.filter((x) => x.k === "h2").length >= 6, "has the main sections");
// style: no em or en dashes, no emoji, no stock filler words
ok(!/[\u2013\u2014]/.test(src), "no em or en dashes");
ok(!/\p{Extended_Pictographic}/u.test(src), "no emoji");
for (const w of ["delve", "seamless", "robust", "leverage", "cutting-edge", "game-changer", "in today's", "it's important to note", "it is important to note", "unlock", "empower", "tapestry", "navigate the"]) ok(!src.toLowerCase().includes(w), `avoids "${w}"`);
console.log(`All ${n} mini-md checks passed`);

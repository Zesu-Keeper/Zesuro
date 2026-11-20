// Tests for lib/identify.ts. Run: node --no-warnings --experimental-transform-types --import ./scripts/ts-resolve.mjs scripts/identify.test.mjs
import assert from "node:assert/strict";
const I = await import(new URL("../src/lib/identify.ts", import.meta.url).pathname);
let n = 0;
const ok = (c, m) => { assert.ok(c, m); n++; };
const kinds = (t) => I.findIdentifying(t).map((f) => `${f.kind}:${f.text}`);

const f1 = kinds("Last Tuesday my manager Gary Pollard told the night shift at Westmead Hospital that 340 records went missing at 3pm on 14 March.");
ok(f1.some((x) => x.startsWith("date:") && /Tuesday/i.test(x)), "a day is found");
ok(f1.includes("role:manager"), "a job is found");
ok(f1.some((x) => x === "name:Gary Pollard"), "a name is found");
ok(f1.some((x) => x.startsWith("place:") && x.includes("Westmead Hospital")), "a place is found");
ok(f1.includes("number:340"), "a number is found");
ok(f1.some((x) => x === "time:3pm"), "a time is found");
ok(f1.some((x) => x.startsWith("date:14 March")), "a date is found");
ok(kinds("Email me at jo.bloggs+x@example.com or call 0412 345 678.").some((x) => x.startsWith("email:")), "an email address is found");
ok(kinds("Email me at jo.bloggs+x@example.com or call 0412 345 678.").some((x) => x.startsWith("phone:")), "a phone number is found");
ok(kinds("See https://intranet.example/doc").some((x) => x.startsWith("link:")), "a link is found");
ok(kinds("The rain will come.").length === 0, "a plain sentence finds nothing");
ok(kinds("It happened. Nobody noticed.").length === 0, "words at the start of sentences are not names");
ok(kinds("I think it will rain in March").every((x) => !x.startsWith("name:")), "months are not names");
ok(kinds("My boss [[Gary Pollard]] knew.").every((x) => !x.includes("Gary")), "hidden parts are not counted");
ok(I.findIdentifying("a ".repeat(10) + Array.from({ length: 40 }, (_, i) => `room ${100 + i}`).join(", ")).length <= 24, "the list is kept short");

// look-alikes and invisible characters
const tagged = "The rep​ort was sеnt to everyone"; // zero-width space, Cyrillic e
const m = I.hiddenMarks(tagged);
ok(m.invisible === 1 && m.lookalike === 1, "an invisible character and a look-alike letter are counted");
ok(I.cleanMarks(tagged) === "The report was sent to everyone", "cleaning restores plain text");
ok(I.hiddenMarks("Привет мир, hello").lookalike === 0, "a word written in Russian is left alone");
ok(I.cleanMarks("Привет мир") === "Привет мир", "and cleaning doesn't change it");
ok(I.hiddenMarks("plain text").invisible === 0 && I.hiddenMarks("plain text").lookalike === 0, "plain text is clean");

// hiding a phrase
ok(I.hidePhrase("Gary said Gary was late", "Gary") === "[[Gary]] said [[Gary]] was late", "every appearance is hidden");
ok(I.hidePhrase("[[Gary]] and Gary", "Gary") === "[[Gary]] and [[Gary]]", "already hidden parts are not wrapped twice");
ok(I.hidePhrase("cost $5.00 (approx)", "$5.00 (approx)") === "cost [[$5.00 (approx)]]", "special characters are matched literally");

console.log(`All ${n} identify checks passed.`);

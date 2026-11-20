// Finds details in a post that could identify the person who wrote it, so the page can point them out before
// sealing. It runs only in the browser and nothing it finds is sent anywhere. It is a prompt, not a filter:
// most sources are found through details like these, not through broken encryption.

export type FindingKind = "name" | "number" | "date" | "time" | "email" | "phone" | "link" | "role" | "place";

export interface Finding {
  kind: FindingKind;
  text: string;
}

const MONTHS = "january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec";
const DAYS = "monday|tuesday|wednesday|thursday|friday|saturday|sunday|yesterday|today|tonight|tomorrow|last night|this morning";
const ROLES =
  "manager|director|supervisor|boss|ceo|cfo|cto|chairman|chairwoman|president|principal|headmaster|teacher|nurse|doctor|surgeon|officer|sergeant|constable|detective|inspector|lawyer|accountant|auditor|engineer|intern|assistant|secretary|receptionist|pastor|priest|coach|captain|minister|councillor|mayor|senator|judge|guard|driver|cleaner|chef|editor|reporter|my husband|my wife|my partner|my ex|my boyfriend|my girlfriend|my brother|my sister|my son|my daughter|my mum|my mom|my dad|my uncle|my aunt|my cousin|my neighbour|my neighbor|my landlord|my colleague|my coworker|my team";
const PLACE_WORDS = "street|st|road|rd|avenue|ave|lane|drive|court|place|hospital|school|college|university|station|office|factory|warehouse|mall|shopping centre|church|mosque|temple|clinic|prison|council|department|ward|floor|building|suburb";

// Words that start sentences or are capitalised for other reasons, and say nothing about anyone.
const COMMON_CAPS = new Set(
  ("I I'm I'll I've I'd The A An This That These Those It It's My Our We He She They You Your His Her Their Its If When While But And Or So " +
    "Then There Here What Who Why How Where Which Not No Yes Mr Mrs Ms Dr OK Okay Also Just Still Even Maybe Please Thanks " +
    "Monday Tuesday Wednesday Thursday Friday Saturday Sunday January February March April May June July August September October November December " +
    "Christmas Easter God English Australian American British").split(" "),
);

function push(out: Finding[], seen: Set<string>, kind: FindingKind, text: string) {
  const t = text.trim();
  if (!t) return;
  const key = kind + ":" + t.toLowerCase();
  if (seen.has(key)) return;
  seen.add(key);
  out.push({ kind, text: t });
}

/** The identifying details found in `text`, in the order they appear, each once. */
export function findIdentifying(text: string): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  const t = text.replace(/\[\[[^\]]*\]\]/g, " "); // already hidden: not public
  for (const m of t.matchAll(/[\w.+-]+@[\w-]+\.[\w.-]+/g)) push(out, seen, "email", m[0]);
  for (const m of t.matchAll(/\b(?:https?:\/\/|www\.)\S+/gi)) push(out, seen, "link", m[0]);
  for (const m of t.matchAll(/(?:\+?\d[\d ()-]{7,}\d)/g)) if (m[0].replace(/\D/g, "").length >= 8) push(out, seen, "phone", m[0]);
  for (const m of t.matchAll(new RegExp(`\\b(?:\\d{1,2}(?:st|nd|rd|th)?\\s+(?:of\\s+)?(?:${MONTHS})|(?:${MONTHS})\\s+\\d{1,2}(?:st|nd|rd|th)?|\\d{1,2}[/.-]\\d{1,2}(?:[/.-]\\d{2,4})?|(?:${DAYS}))\\b`, "gi")))
    push(out, seen, "date", m[0]);
  for (const m of t.matchAll(/\b(?:\d{1,2}(?::\d{2})?\s?(?:am|pm)|\d{1,2}:\d{2})\b/gi)) push(out, seen, "time", m[0]);
  for (const m of t.matchAll(/\$?\b\d[\d,.]*\d\b|\$\d+\b/g)) {
    const digits = m[0].replace(/\D/g, "");
    if (digits.length >= 3 && !seen.has("phone:" + m[0].trim().toLowerCase())) push(out, seen, "number", m[0]);
  }
  for (const m of t.matchAll(new RegExp(`\\b(?:${ROLES})\\b`, "gi"))) push(out, seen, "role", m[0]);
  const placeWords = new Set(PLACE_WORDS.split("|"));
  for (const m of t.matchAll(/\b((?:[A-Z][\w'-]+\s+)+?)([A-Za-z]+)\b/g))
    if (placeWords.has(m[2].toLowerCase())) push(out, seen, "place", m[0]);
  // Capitalised words that are not at the start of a sentence: usually names of people, firms or places.
  for (const m of t.matchAll(/(^|[^.!?\n]\s+)((?:[A-Z][a-z'’-]+)(?:\s+[A-Z][a-z'’-]+)*)/g)) {
    if (m[1] === "") continue; // start of the text
    const words = m[2].split(/\s+/).filter((w) => !COMMON_CAPS.has(w.replace(/[’']s$/, "")));
    if (!words.length) continue;
    const phrase = words.join(" ");
    if (!out.some((f) => f.text.includes(phrase))) push(out, seen, "name", phrase);
  }
  return out.slice(0, 24);
}

export const KIND_LABEL: Record<FindingKind, string> = {
  name: "a name",
  number: "a number",
  date: "a date or day",
  time: "a time",
  email: "an email address",
  phone: "a phone number",
  link: "a link",
  role: "a job or relationship",
  place: "a place",
};

// ---------- look-alike letters and invisible characters ----------
// Documents passed around a workplace are sometimes given to each person with tiny invisible differences:
// zero-width characters, or Cyrillic and Greek letters that look exactly like Latin ones. Copying text from
// such a document copies its tag.

const INVISIBLE = /[­͏؜ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁤⁦-⁯ㅤ﻿ﾠ]/g;
const LOOKALIKE: Record<string, string> = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h",
  "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
  "ο": "o", "α": "a", "ν": "v", "ι": "i", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
  " ": " ", " ": " ", " ": " ", " ": " ", " ": " ",
};
const LOOKALIKE_RE = new RegExp(`[${Object.keys(LOOKALIKE).join("")}]`, "g");

/** How many invisible characters and look-alike letters the text holds. Look-alikes count only inside otherwise Latin words. */
export function hiddenMarks(text: string): { invisible: number; lookalike: number } {
  const invisible = (text.match(INVISIBLE) ?? []).length;
  let lookalike = 0;
  for (const w of text.split(/\s+/)) {
    if (!/[A-Za-z]/.test(w)) continue; // a whole word in Cyrillic or Greek is just that language
    lookalike += (w.match(LOOKALIKE_RE) ?? []).length;
  }
  lookalike += (text.match(/[     ]/g) ?? []).length;
  return { invisible, lookalike };
}

/** The text with invisible characters removed and look-alike letters inside Latin words replaced. */
export function cleanMarks(text: string): string {
  return text
    .replace(INVISIBLE, "")
    .split(/(\s+)/)
    .map((w) => (/[A-Za-z]/.test(w) ? w.replace(LOOKALIKE_RE, (c) => LOOKALIKE[c] ?? c) : w))
    .join("")
    .replace(/[     ]/g, " ");
}

/** Wraps every appearance of `phrase` in [[ ]] so it stays hidden until the post is revealed. */
export function hidePhrase(text: string, phrase: string): string {
  if (!phrase.trim()) return text;
  const esc = phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // Leave anything already inside [[ ]] alone.
  return text
    .split(/(\[\[[^\]]*\]\])/)
    .map((part) => (part.startsWith("[[") ? part : part.replace(new RegExp(esc, "g"), (m) => `[[${m}]]`)))
    .join("");
}

// Characters that change how text is displayed without being visible. In a permanent public
// record they could be used to make a statement read differently from what was sealed.

/** Bidirectional controls: they reorder how the text around them is drawn. */
// eslint-disable-next-line no-control-regex
const BIDI = /[؜‎‏‪-‮⁦-⁩]/;
/** Control characters other than newline and tab. */
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/;

export function hasHiddenControls(s: string): boolean {
  return BIDI.test(s) || CONTROL.test(s);
}

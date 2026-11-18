// Thresholds shared by the server rules and the pages that explain them.

/** Spam flags stop adding to an entry's ranking penalty past this many (2^10 - 1 = 1,023 likes). */
export const SPAM_CAP = 10;
/** Net likes before an entry's links become clickable. Comments' links never are. */
export const LINKS_AT = 3;

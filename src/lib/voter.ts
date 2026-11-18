// Browser only. Stops this browser voting or flagging the same thing twice, without making
// its actions linkable. The browser keeps one random secret; what it sends for each entry (and
// each kind of action on it) is a hash of that secret and the entry's id. Two votes by one
// browser on different entries therefore look unrelated, to the server and to its backups.
// The server stores only a hash of what it is sent.

const SECRET = "whenisaid.voter.v2";

function secret(): string {
  try {
    let t = localStorage.getItem(SECRET);
    if (!t || !/^[0-9a-f]{64}$/.test(t)) {
      const b = crypto.getRandomValues(new Uint8Array(32));
      t = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
      localStorage.setItem(SECRET, t);
    }
    return t;
  } catch {
    return "";
  }
}

/** A token for one action on one thing, e.g. "like:<uid>". Empty if storage is unavailable. */
export async function voterTokenFor(scope: string): Promise<string> {
  const s = secret();
  if (!s) return "";
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`whenisaid:voter-scope:v2:${s}:${scope}`));
  return Array.from(new Uint8Array(d), (x) => x.toString(16).padStart(2, "0")).join("");
}

#!/usr/bin/env node
// Zesuro admin tool. Run on the server, from the app folder, as the app's user:
//   sudo -u whenisaid node scripts/admin.mjs <command>
// There is deliberately no web admin page: nothing to log in to means nothing to break into.
//
// Nothing is removed or hidden automatically: readers' spam flags only lower an entry's
// ranking. The remove/delist commands below are the operator's own, manual decisions.
//
//   reported                      most-flagged comments and entries
//   block <domain>                refuse new posts that mention a site (earlier ones stay)
//   unblock <domain>              stop blocking
//   blocked                       list blocked sites
//   remove-comment <id> [--same-text]   remove a comment's text (and every copy of it)
//   clear-spam <c<id> | entry-uid>   reset the spam flags on a comment or an entry
//   witnesses                     mirrors whose signatures on anchors are accepted
//   witness-add <key> <name>      accept a mirror as a witness (its operator sends you the key)
//   witness-remove <key>          stop accepting it
//   delist <entry-uid>            take an entry off the lists (it stays in the record)
//   relist <entry-uid>            put it back on the lists
//
// Removing a comment's text cannot be undone. Entries are never removed, only delisted.
import { DatabaseSync } from "node:sqlite";

const db = new DatabaseSync(process.env.DB || "data/whenisaid.db");
db.exec("PRAGMA busy_timeout = 10000;");
const [cmd, arg, flag] = process.argv.slice(2);
const now = Date.now();
const die = (m) => { console.error(m); process.exit(1); };
const domainOk = (d) => /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/.test(d);
const like = (s) => "%" + s.replace(/[\\%_]/g, (c) => "\\" + c) + "%";
/** True if the text mentions the domain itself or a subdomain of it (not just a longer name). */
const mentions = (text, d) =>
  new RegExp(`(^|[^a-z0-9-])([a-z0-9-]+\\.)*${d.replace(/\./g, "\\.")}($|[^a-z0-9.-]|\\.(?![a-z0-9]))`, "i")
    .test(text.normalize("NFKC"));
const removeText = (ids, reason) => {
  const st = db.prepare("UPDATE comments SET text = '', removed_at = ?, removed_reason = ? WHERE id = ? AND removed_at IS NULL");
  let n = 0;
  for (const id of ids) n += Number(st.run(now, reason, id).changes);
  return n;
};

switch (cmd) {
  case "reported": {
    console.log("Comments (id, spam flags, entry, text):");
    for (const r of db.prepare("SELECT id, reports, entry_uid, substr(text, 1, 80) AS t FROM comments WHERE reports > 0 AND removed_at IS NULL ORDER BY reports DESC, id DESC LIMIT 30").all())
      console.log(`  c${r.id}  ${r.reports}  ${r.entry_uid}  ${JSON.stringify(r.t)}`);
    console.log("Entries (uid, spam flags, likes, listing, title):");
    for (const r of db.prepare("SELECT uid, reports, likes, listing, substr(title, 1, 60) AS t FROM entries WHERE reports > 0 ORDER BY reports DESC, seq DESC LIMIT 30").all())
      console.log(`  ${r.uid}  ${r.reports}  ${r.likes}  ${r.listing === 1 ? "delisted" : "listed"}  ${JSON.stringify(r.t)}`);
    break;
  }
  case "block": {
    const d = (arg || "").toLowerCase().replace(/^www\./, "");
    if (!domainOk(d)) die("Give a domain, e.g. spam-site.example");
    db.prepare("INSERT OR IGNORE INTO blocked_domains (domain, added_at) VALUES (?, ?)").run(d, now);
    console.log(`Blocked ${d}. New posts that mention it are refused; earlier ones are untouched.`);
    break;
  }
  case "unblock": {
    const n = db.prepare("DELETE FROM blocked_domains WHERE domain = ?").run((arg || "").toLowerCase()).changes;
    console.log(n ? `Unblocked ${arg}.` : "That domain wasn't blocked.");
    break;
  }
  case "blocked":
    for (const r of db.prepare("SELECT domain, added_at FROM blocked_domains ORDER BY domain").all())
      console.log(`${r.domain}  (since ${new Date(r.added_at).toISOString().slice(0, 10)})`);
    break;
  case "remove-comment": {
    const id = Number((arg || "").replace(/^c/, ""));
    const c = db.prepare("SELECT id, dup_hash FROM comments WHERE id = ?").get(id);
    if (!c) die("No such comment.");
    const ids = flag === "--same-text"
      ? db.prepare("SELECT id FROM comments WHERE dup_hash = ?").all(c.dup_hash).map((r) => r.id)
      : [id];
    console.log(`Removed the text of ${removeText(ids, "removed by admin")} comment(s). Their place in the record stays.`);
    break;
  }
  case "clear-spam": {
    const a = arg || "";
    let n;
    if (/^c?\d+$/.test(a)) {
      const id = Number(a.replace(/^c/, ""));
      db.prepare("DELETE FROM comment_reports WHERE comment_id = ?").run(id);
      n = db.prepare("UPDATE comments SET reports = 0 WHERE id = ?").run(id).changes;
    } else {
      db.prepare("DELETE FROM entry_reports WHERE entry_uid = ?").run(a);
      n = db.prepare("UPDATE entries SET reports = 0 WHERE uid = ?").run(a).changes;
    }
    console.log(n ? `Cleared the spam flags on ${a}.` : "Nothing with that id.");
    break;
  }
  case "witness-add": {
    // A mirror operator sends you the key their mirror printed. The name is shown publicly.
    const name = process.argv.slice(4).join(" ").trim();
    if (!/^[A-Za-z0-9_-]{43}$/.test(arg || "") || !name || name.length > 60) die("Use: witness-add <key> <name shown on the Anchors page>");
    db.prepare("INSERT INTO witness_keys (key, name, added_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET name = excluded.name").run(arg, name, now);
    console.log(`Witness "${name}" accepted. Its signatures on anchors will now be recorded and shown.`);
    break;
  }
  case "witness-remove": {
    const n = db.prepare("DELETE FROM witness_keys WHERE key = ?").run(arg || "").changes;
    console.log(n ? "Witness removed. Its earlier signatures are kept but no longer shown." : "No such witness.");
    break;
  }
  case "witnesses":
    for (const r of db.prepare("SELECT k.key, k.name, (SELECT COUNT(*) FROM anchor_witnesses w WHERE w.key = k.key) AS n, (SELECT MAX(at) FROM anchor_witnesses w WHERE w.key = k.key) AS last FROM witness_keys k ORDER BY k.name").all())
      console.log(`${r.key}  ${r.name}  ${r.n} anchor(s) signed${r.last ? `, last ${new Date(r.last).toISOString()}` : ""}`);
    break;
  case "delist": case "relist": {
    const v = cmd === "delist" ? 1 : 0;
    const n = db.prepare("UPDATE entries SET listing = ? WHERE uid = ?").run(v, arg || "").changes;
    console.log(n ? `Entry ${arg}: ${v ? "delisted" : "listed"}.` : "No such entry.");
    break;
  }
  default:
    console.log("Commands: reported | block <domain> | unblock <domain> | blocked | remove-comment <id> [--same-text] | clear-spam <c<id>|uid> | delist <uid> | relist <uid> | witnesses | witness-add <key> <name> | witness-remove <key>");
    process.exit(cmd ? 1 : 0);
}

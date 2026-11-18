import Linkify from "./Linkify";

const MARK = "";

/**
 * Shows sealed text. Each redaction is a block until the entry is released, then the real
 * passage. `owner` shows the author their own passages while they are still hidden from the public.
 */
export default function RedactedText({
  text,
  parts,
  owner = false,
  links = true,
}: {
  text: string;
  parts: string[] | null;
  owner?: boolean;
  /** False until an entry has earned clickable links. */
  links?: boolean;
}) {
  const segs = text.split(MARK);
  return (
    <>
      {segs.map((seg, i) => (
        <span key={i}>
          <Linkify text={seg} active={links} />
          {i < segs.length - 1 ? (
            parts && parts[i] !== undefined ? (
              <mark className={owner ? "unredacted mine" : "unredacted"} title={owner ? "Hidden from the public until release" : "Was redacted"}>
                {parts[i]}
              </mark>
            ) : (
              <span className="redacted" role="img" aria-label="Redacted until released">
                █████
              </span>
            )
          ) : null}
        </span>
      ))}
    </>
  );
}

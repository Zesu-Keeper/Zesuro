import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

/** Old address of the record. Its pages were newest-first, so they carry on at /new. */
export default async function OldRecord({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  const p = new URLSearchParams();
  for (const k of ["status", "before", "q", "from", "to"]) {
    const v = sp[k];
    if (typeof v === "string" && v) p.set(k, v);
  }
  const s = p.toString();
  redirect("/new" + (s ? "?" + s : ""));
}

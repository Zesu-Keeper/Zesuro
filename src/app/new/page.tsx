import RecordView, { type RecordParams } from "@/components/RecordView";

export const dynamic = "force-dynamic";
export const metadata = { title: "New on the Record · Zesuro" };

export default async function New({ searchParams }: { searchParams: Promise<RecordParams> }) {
  return <RecordView sp={await searchParams} sort="new" />;
}

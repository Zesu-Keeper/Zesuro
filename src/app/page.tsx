import RecordView, { type RecordParams } from "@/components/RecordView";

export const dynamic = "force-dynamic";
export const metadata = { title: "Popular posts · Zesuro" };

export default async function Home({ searchParams }: { searchParams: Promise<RecordParams> }) {
  return <RecordView sp={await searchParams} sort="top" />;
}

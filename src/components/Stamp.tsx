"use client";

import { useEffect, useState } from "react";

function utc(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

/** Renders a moment in time. Server render is UTC (stable); the browser then adds local time. */
export default function Stamp({ ms }: { ms: number }) {
  const [local, setLocal] = useState<string | null>(null);
  useEffect(() => {
    setLocal(
      new Date(ms).toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      }),
    );
  }, [ms]);
  return (
    <time dateTime={new Date(ms).toISOString()} title={utc(ms)}>
      {local ?? utc(ms)}
    </time>
  );
}

import { formatTime } from "@/lib/format";

export default function TimeAgo({ value }: { value?: string }) {
  return <time dateTime={value} title={value}>{formatTime(value)}</time>;
}

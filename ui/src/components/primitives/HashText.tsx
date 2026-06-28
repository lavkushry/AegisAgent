import CopyButton from "./CopyButton";

export default function HashText({ value, head = 12, tail = 8 }: { value?: string; head?: number; tail?: number }) {
  if (!value) return <span className="font-mono text-[var(--text-muted)]">unknown</span>;
  const display = value.length > head + tail + 1 ? `${value.slice(0, head)}…${value.slice(-tail)}` : value;
  return (
    <span className="inline-flex items-center gap-2 font-mono" title={value}>
      <span>{display}</span>
      <CopyButton value={value} label="Copy hash" />
    </span>
  );
}

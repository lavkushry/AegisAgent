import { getSeverityStyle } from "./severityStyles";

export default function SeverityBadge({ severity }: { severity: string }) {
  const style = getSeverityStyle(severity);
  return (
    <span
      className={`inline-flex rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${style.badge}`}
    >
      {severity || "unknown"}
    </span>
  );
}
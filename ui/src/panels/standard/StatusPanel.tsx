import { AlertTriangle, CheckCircle2, HelpCircle } from "lucide-react";

import { cell } from "@/datasources/frame";
import type { PanelProps } from "../types";

interface StatusPanelOptions {
  field?: string;
  healthyValues?: string[];
  failedValues?: string[];
}

export default function StatusPanel({ data, definition }: PanelProps<StatusPanelOptions>) {
  const options = definition.options ?? {};
  const value = String(cell(data, options.field ?? "status", 0) ?? "unknown");
  const normalized = value.toLowerCase();
  const healthy = (options.healthyValues ?? ["ok", "healthy", "verified", "active"]).includes(normalized);
  const failed = (options.failedValues ?? ["failed", "broken", "tampered", "error"]).includes(normalized);
  const Icon = healthy ? CheckCircle2 : failed ? AlertTriangle : HelpCircle;
  const color = healthy ? "var(--state-verified)" : failed ? "var(--state-failed)" : "var(--state-pending)";

  return (
    <div className="flex h-full items-center gap-3" style={{ color }}>
      <Icon size={22} aria-hidden="true" />
      <span className="text-lg font-semibold capitalize">{value}</span>
    </div>
  );
}

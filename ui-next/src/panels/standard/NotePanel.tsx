import { AlertTriangle, Info } from "lucide-react";
import type { PanelProps } from "../types";

export interface NotePanelOptions {
  body?: string;
  variant?: "info" | "unavailable" | "advisory";
}

/** Static metric definitions and honest backend-unavailable notices — no fetch. */
export default function NotePanel({ definition }: PanelProps<NotePanelOptions>) {
  const { body, variant = "info" } = definition.options ?? {};
  const isUnavailable = variant === "unavailable";
  const Icon = isUnavailable ? AlertTriangle : Info;
  const color = isUnavailable
    ? "var(--state-pending)"
    : variant === "advisory"
      ? "var(--text-secondary)"
      : "var(--text-muted)";

  return (
    <div className="flex h-full flex-col justify-center gap-2 text-xs leading-relaxed" style={{ color }}>
      <div className="flex items-start gap-2">
        <Icon size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
        <p className="whitespace-pre-wrap">{body}</p>
      </div>
      {variant === "advisory" ? (
        <span className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Advisory only — not enforcement</span>
      ) : null}
    </div>
  );
}
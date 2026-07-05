export interface SeverityStyle {
  badge: string;
  card: string;
}

export function getSeverityStyle(severity: string): SeverityStyle {
  switch (String(severity).toLowerCase()) {
    case "high":
      return {
        badge: "bg-red-500/20 border border-red-500/40 text-red-400",
        card: "border-l-4 border-l-red-500 bg-[var(--surface-panel)] hover:bg-[var(--surface-elevated)] border-r border-y border-[var(--border-default)]",
      };
    case "medium":
      return {
        badge: "bg-amber-500/20 border border-amber-500/40 text-amber-400",
        card: "border-l-4 border-l-amber-500 bg-[var(--surface-panel)] hover:bg-[var(--surface-elevated)] border-r border-y border-[var(--border-default)]",
      };
    case "low":
      return {
        badge: "bg-yellow-500/20 border border-yellow-500/40 text-yellow-400",
        card: "border-l-4 border-l-yellow-500 bg-[var(--surface-panel)] hover:bg-[var(--surface-elevated)] border-r border-y border-[var(--border-default)]",
      };
    case "info":
      return {
        badge: "bg-blue-500/20 border border-blue-500/40 text-blue-400",
        card: "border-l-4 border-l-blue-500 bg-[var(--surface-panel)] hover:bg-[var(--surface-elevated)] border-r border-y border-[var(--border-default)]",
      };
    default:
      return {
        badge: "bg-slate-500/20 border border-slate-500/40 text-slate-400",
        card: "border-l-4 border-l-slate-500 bg-[var(--surface-panel)]/40 hover:bg-[var(--border-default)]/50 border-r border-y border-[var(--border-default)]",
      };
  }
}
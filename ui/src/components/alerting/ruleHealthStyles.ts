import type { RuleHealthStatus } from "./ruleHealth";

export function ruleHealthBadgeClass(status: RuleHealthStatus): string {
  switch (status) {
    case "firing":
      return "bg-red-500/20 border-red-500/40 text-red-400";
    case "normal":
      return "bg-green-500/20 border-green-500/40 text-green-400";
    case "error":
      return "bg-red-950/40 border-red-500/30 text-red-300";
    case "stale":
      return "bg-amber-500/20 border-amber-500/40 text-amber-400";
    default:
      return "bg-[var(--border-default)]/40 border-[var(--border-default)] text-[var(--text-muted)]";
  }
}
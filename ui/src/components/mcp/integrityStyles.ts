import type { McpIntegrityStatus } from "./driftState";

export function integrityBadgeClass(status: McpIntegrityStatus): string {
  switch (status) {
    case "healthy":
      return "bg-green-500/20 border-green-500/40 text-green-400";
    case "drifted":
      return "bg-amber-500/20 border-amber-500/40 text-amber-400";
    case "quarantined":
      return "bg-red-500/20 border-red-500/40 text-red-400";
    default:
      return "bg-[var(--border-default)]/40 border-[var(--border-default)] text-[var(--text-muted)]";
  }
}
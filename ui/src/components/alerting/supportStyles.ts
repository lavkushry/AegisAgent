import type { ChannelSupport } from "./supportStates";

export function channelSupportBadgeClass(support: ChannelSupport): string {
  switch (support) {
    case "supported":
      return "bg-green-500/20 border-green-500/40 text-green-400";
    case "standby":
      return "bg-[var(--border-default)]/40 border-[var(--border-default)] text-[var(--text-muted)]";
    default:
      return "bg-red-950/30 border-red-500/30 text-red-300";
  }
}

export function channelSupportLabel(support: ChannelSupport): string {
  switch (support) {
    case "supported":
      return "Supported";
    case "standby":
      return "Standby";
    default:
      return "Unsupported";
  }
}
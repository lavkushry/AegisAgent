import React from "react";
import { pillStyle } from "./pill";

type StatusConfig = { label: string; colorVar: string; bold?: boolean };

// Lifecycle status for agents and MCP servers. A distinct vocabulary from
// severity/decision/trust, so it gets its own reserved mapping.
const STATUSES: Record<string, StatusConfig> = {
  active: { label: "Active", colorVar: "--state-verified" },
  healthy: { label: "Healthy", colorVar: "--state-verified" },
  frozen: { label: "Frozen", colorVar: "--state-pending" },
  drifted: { label: "Drifted", colorVar: "--sev-medium" },
  quarantined: { label: "Quarantined", colorVar: "--sev-critical", bold: true },
  revoked: { label: "Revoked", colorVar: "--decision-deny" },
  dead: { label: "Dead", colorVar: "--decision-deny" },
  deleted: { label: "Deleted", colorVar: "--text-muted" },
};

type Props = {
  status: string | undefined;
  size?: "sm" | "md";
};

const SIZE_CLASS: Record<NonNullable<Props["size"]>, string> = {
  sm: "px-2 py-0.5 text-[10px] rounded",
  md: "px-2.5 py-0.5 text-xs rounded-full",
};

/** Agent / MCP-server lifecycle status, rendered with a text label. */
export default function StatusBadge({ status, size = "md" }: Props) {
  const key = String(status ?? "").toLowerCase();
  const config = STATUSES[key];
  const label = config ? config.label : status || "Unknown";
  const colorVar = config ? config.colorVar : "--sev-info";

  return (
    <span
      className={`inline-flex items-center font-semibold border ${SIZE_CLASS[size]}`}
      style={pillStyle(colorVar, config?.bold)}
    >
      {label}
    </span>
  );
}

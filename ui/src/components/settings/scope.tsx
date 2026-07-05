import React from "react";

export type SettingScope = "gateway" | "local" | "unsupported" | "read-only";

const SCOPE_CLASS: Record<SettingScope, string> = {
  gateway: "bg-green-500/20 border-green-500/40 text-green-400",
  local: "bg-blue-500/20 border-blue-500/40 text-blue-400",
  "read-only": "bg-[var(--border-default)]/40 border-[var(--border-default)] text-[var(--text-muted)]",
  unsupported: "bg-amber-950/30 border-amber-500/30 text-amber-300",
};

const SCOPE_LABEL: Record<SettingScope, string> = {
  gateway: "Gateway",
  local: "Local only",
  "read-only": "Read-only",
  unsupported: "Unsupported",
};

export function SettingScopeBadge({ scope }: { scope: SettingScope }) {
  return (
    <span
      className={`inline-block rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase ${SCOPE_CLASS[scope]}`}
    >
      {SCOPE_LABEL[scope]}
    </span>
  );
}
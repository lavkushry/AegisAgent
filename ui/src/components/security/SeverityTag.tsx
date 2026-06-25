import React from "react";
import { pillStyle } from "./pill";

type SeverityConfig = { label: string; colorVar: string; bold?: boolean };

const SEVERITIES: Record<string, SeverityConfig> = {
  critical: { label: "Critical", colorVar: "--sev-critical", bold: true },
  high: { label: "High", colorVar: "--sev-high" },
  medium: { label: "Medium", colorVar: "--sev-medium" },
  low: { label: "Low", colorVar: "--sev-low" },
  info: { label: "Info", colorVar: "--sev-info" },
};

type Props = {
  severity: string | undefined;
};

/** Detection / incident severity, icon-free but always with a text label. */
export default function SeverityTag({ severity }: Props) {
  const key = String(severity ?? "").toLowerCase();
  const config = SEVERITIES[key] ?? SEVERITIES.info;
  const label = key && SEVERITIES[key] ? config.label : severity || "Info";

  return (
    <span
      className="inline-flex items-center px-2 py-0.5 text-[10px] uppercase tracking-wide rounded border"
      style={pillStyle(config.colorVar, config.bold)}
    >
      {label}
    </span>
  );
}

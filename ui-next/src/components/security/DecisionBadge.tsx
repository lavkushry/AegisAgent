import { Ban, Check, Clock, EyeOff, HelpCircle, ShieldAlert } from "lucide-react";
import type { ComponentType } from "react";
import { pillStyle } from "./pill";

type DecisionConfig = {
  label: string;
  colorVar: string;
  Icon: ComponentType<{ size?: number }>;
};

const DECISIONS: Record<string, DecisionConfig> = {
  allow: { label: "Allow", colorVar: "--decision-allow", Icon: Check },
  deny: { label: "Deny", colorVar: "--decision-deny", Icon: Ban },
  require_approval: {
    label: "Require Approval",
    colorVar: "--decision-approval",
    Icon: Clock,
  },
  approval: {
    label: "Require Approval",
    colorVar: "--decision-approval",
    Icon: Clock,
  },
  quarantine: {
    label: "Quarantine",
    colorVar: "--decision-quarantine",
    Icon: ShieldAlert,
  },
  redact: { label: "Redact", colorVar: "--decision-redact", Icon: EyeOff },
};

export function DecisionBadge({ decision }: { decision: string | undefined }) {
  const key = String(decision ?? "").toLowerCase();
  const config = DECISIONS[key];

  if (!config) {
    return (
      <span
        className="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs"
        style={pillStyle("--sev-info")}
      >
        <HelpCircle size={12} />
        {decision || "unknown"}
      </span>
    );
  }

  const { label, colorVar, Icon } = config;
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs"
      style={pillStyle(colorVar)}
    >
      <Icon size={12} />
      {label}
    </span>
  );
}

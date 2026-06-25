import React from "react";
import { Check, Ban, Clock, ShieldAlert, EyeOff, HelpCircle } from "lucide-react";
import { pillStyle } from "./pill";

type DecisionConfig = {
  label: string;
  colorVar: string;
  Icon: React.ComponentType<{ size?: number }>;
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

type Props = {
  decision: string | undefined;
};

/**
 * The policy decision, rendered as icon + label (never color alone) so it
 * is legible under color-blindness and to screen readers.
 */
export default function DecisionBadge({ decision }: Props) {
  const key = String(decision ?? "").toLowerCase();
  const config = DECISIONS[key];

  if (!config) {
    return (
      <span
        className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-full border"
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
      className="inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded-full border"
      style={pillStyle(colorVar)}
    >
      <Icon size={12} />
      {label}
    </span>
  );
}

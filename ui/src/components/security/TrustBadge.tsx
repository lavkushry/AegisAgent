import React from "react";
import { pillStyle } from "./pill";

type TrustConfig = { colorVar: string; bold?: boolean };

// The six deterministic trust-provenance levels, ordered most- to
// least-trusted. Classifiers may only tighten a level, never loosen it.
const TRUST_LEVELS: Record<string, TrustConfig> = {
  trusted_internal_signed: { colorVar: "--trust-internal-signed" },
  trusted_internal_unsigned: { colorVar: "--trust-internal-unsigned" },
  semi_trusted_customer: { colorVar: "--trust-customer" },
  untrusted_external: { colorVar: "--trust-external" },
  malicious_suspected: { colorVar: "--trust-malicious", bold: true },
  unknown: { colorVar: "--trust-unknown" },
};

type Props = {
  trust: string | undefined;
};

/** The source trust level of the triggering content (provenance gating). */
export default function TrustBadge({ trust }: Props) {
  const key = String(trust ?? "").toLowerCase();
  const config = TRUST_LEVELS[key] ?? TRUST_LEVELS.unknown;
  const label = key && TRUST_LEVELS[key] ? key : "unknown";

  return (
    <span
      className="inline-flex items-center text-[10px] font-mono px-1.5 py-0.5 rounded border"
      style={pillStyle(config.colorVar, config.bold)}
    >
      {label}
    </span>
  );
}

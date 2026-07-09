import { pillStyle } from "./pill";

const TRUST_LEVELS: Record<string, { colorVar: string; bold?: boolean }> = {
  trusted_internal_signed: { colorVar: "--trust-internal-signed" },
  trusted_internal_unsigned: { colorVar: "--trust-internal-unsigned" },
  semi_trusted_customer: { colorVar: "--trust-customer" },
  untrusted_external: { colorVar: "--trust-external" },
  malicious_suspected: { colorVar: "--trust-malicious", bold: true },
  unknown: { colorVar: "--trust-unknown" },
};

export function TrustBadge({ trust }: { trust: string | undefined }) {
  const key = String(trust ?? "").toLowerCase();
  const config = TRUST_LEVELS[key] ?? TRUST_LEVELS.unknown;
  const label = key && TRUST_LEVELS[key] ? key : "unknown";

  return (
    <span
      className="inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px]"
      style={pillStyle(config.colorVar, config.bold)}
    >
      {label}
    </span>
  );
}

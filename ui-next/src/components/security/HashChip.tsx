import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { truncateHash } from "@/lib/format";

type HashKind = "action" | "receipt" | "manifest";

const ACCENT: Record<HashKind, string> = {
  action: "--brand",
  receipt: "--state-verified",
  manifest: "--sev-low",
};

export function HashChip({
  hash,
  kind = "action",
  head = 8,
  tail = 4,
}: {
  hash: string | undefined;
  kind?: HashKind;
  head?: number;
  tail?: number;
}) {
  const [copied, setCopied] = useState(false);

  if (!hash) {
    return (
      <span className="font-mono text-xs text-[var(--text-muted)]">N/A</span>
    );
  }

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopied(false);
    }
  };

  return (
    <span
      className="inline-flex items-center gap-1.5 whitespace-nowrap font-mono text-xs"
      style={{
        color: "var(--text-secondary)",
        borderLeft: `2px solid var(${ACCENT[kind]})`,
        paddingLeft: "6px",
      }}
    >
      <span aria-label={`${kind} hash ${hash}`}>
        {truncateHash(hash, head, tail)}
      </span>
      <button
        type="button"
        onClick={handleCopy}
        className="cursor-pointer text-[var(--text-muted)] hover:text-[var(--text-primary)]"
        aria-label="Copy full hash"
        title="Copy full hash"
      >
        {copied ? (
          <Check size={12} style={{ color: "var(--state-verified)" }} />
        ) : (
          <Copy size={12} />
        )}
      </button>
    </span>
  );
}

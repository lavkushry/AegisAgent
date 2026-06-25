"use client";

import React, { useState } from "react";
import { Copy, Check } from "lucide-react";
import { truncateHash } from "@/lib/format";

type HashKind = "action" | "receipt" | "manifest";

const ACCENT: Record<HashKind, string> = {
  action: "--brand",
  receipt: "--state-verified",
  manifest: "--sev-low",
};

type Props = {
  hash: string | undefined;
  kind?: HashKind;
  head?: number;
  tail?: number;
  onDrilldown?: () => void;
};

/**
 * A truncated, monospace hash with a one-click copy of the FULL value.
 * The display is lossy; the clipboard never is. A 1px left accent encodes
 * the hash kind. Never wraps; never renders raw secrets.
 */
export default function HashChip({
  hash,
  kind = "action",
  head = 8,
  tail = 4,
  onDrilldown,
}: Props) {
  const [copied, setCopied] = useState(false);

  if (!hash) {
    return <span className="text-xs font-mono text-[var(--text-muted)]">N/A</span>;
  }

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      // Clipboard may be unavailable (insecure context); fail quietly.
      setCopied(false);
    }
  };

  return (
    <span
      className="inline-flex items-center gap-1.5 text-xs font-mono whitespace-nowrap"
      style={{
        color: "var(--text-secondary)",
        borderLeft: `2px solid var(${ACCENT[kind]})`,
        paddingLeft: "6px",
      }}
    >
      {onDrilldown ? (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onDrilldown();
          }}
          className="hover:text-[var(--text-primary)] cursor-pointer"
          aria-label={`Inspect ${kind} hash ${hash}`}
        >
          {truncateHash(hash, head, tail)}
        </button>
      ) : (
        <span aria-label={`${kind} hash ${hash}`}>{truncateHash(hash, head, tail)}</span>
      )}
      <button
        type="button"
        onClick={handleCopy}
        className="text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
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

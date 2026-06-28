"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

export default function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1_500);
  };
  return (
    <button type="button" onClick={copy} className="inline-flex items-center gap-1 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]" aria-label={`${label}: ${value}`}>
      {copied ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
      <span>{copied ? "Copied" : label}</span>
    </button>
  );
}

"use client";

import { useState } from "react";

export default function RedactedValue({ value, allowReveal = false }: { value: string; allowReveal?: boolean }) {
  const [revealed, setRevealed] = useState(false);
  return <span className="inline-flex items-center gap-2 font-mono"><span>{revealed ? value : "••••••••"}</span>{allowReveal ? <button type="button" onClick={() => setRevealed((current) => !current)} className="text-xs text-[var(--text-secondary)]">{revealed ? "Hide" : "Reveal"}</button> : null}</span>;
}

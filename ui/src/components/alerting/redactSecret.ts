const REDACTED = "••••••••";

/** Never render raw secrets in the UI after initial creation. */
export function redactSecret(value: string | null | undefined): string {
  if (!value || !value.trim()) return "—";
  return REDACTED;
}

export function isRedactedDisplay(value: string): boolean {
  return value === REDACTED;
}

export function hashPreview(hash: string | null | undefined): string {
  if (!hash) return "—";
  if (hash.length <= 16) return hash;
  return `${hash.slice(0, 8)}…${hash.slice(-8)}`;
}
/**
 * Formatting helpers for evidence display. Pure, dependency-free.
 * Hashes are never wrapped or lossily shortened — the truncation here is
 * display-only; the full value is always available to copy.
 */

/** Truncate a hash for display while preserving head and tail. */
export function truncateHash(hash: string, head = 8, tail = 4): string {
  if (!hash) return "";
  const raw = hash.startsWith("sha256:") ? hash.slice("sha256:".length) : hash;
  const prefix = hash.startsWith("sha256:") ? "sha256:" : "";
  if (raw.length <= head + tail + 1) return hash;
  return `${prefix}${raw.slice(0, head)}…${raw.slice(-tail)}`;
}

/** Best-effort local time string from an ISO/epoch value. */
export function formatTime(value: string | number | undefined | null): string {
  if (value === undefined || value === null || value === "") return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleTimeString();
}

/** Compact relative-time label ("3m", "2h", "5d") from an ISO/epoch value. */
export function formatRelative(value: string | number | undefined | null): string {
  if (value === undefined || value === null || value === "") return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  const deltaSec = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (deltaSec < 60) return `${deltaSec}s`;
  const min = Math.floor(deltaSec / 60);
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h`;
  return `${Math.floor(hr / 24)}d`;
}

/** Normalize a free-form error into a user-safe message. */
export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return "Unexpected error";
}

const RANGE_MS: Record<string, number> = {
  "1h": 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

/**
 * Convert a relative range token ("24h", "7d", …) to an RFC3339 lower bound
 * (now - range). Returns undefined for unknown tokens (no time filter).
 */
export function relativeRangeToFrom(range: string): string | undefined {
  const ms = RANGE_MS[range];
  if (!ms) return undefined;
  return new Date(Date.now() - ms).toISOString();
}

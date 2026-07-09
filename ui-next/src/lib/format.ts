/** Display-only hash truncation; full value stays available for copy. */
export function truncateHash(hash: string, head = 8, tail = 4): string {
  if (!hash) return "";
  const raw = hash.startsWith("sha256:") ? hash.slice("sha256:".length) : hash;
  const prefix = hash.startsWith("sha256:") ? "sha256:" : "";
  if (raw.length <= head + tail + 1) return hash;
  return `${prefix}${raw.slice(0, head)}…${raw.slice(-tail)}`;
}

export function formatTime(value: string | number | undefined | null): string {
  if (value === undefined || value === null || value === "") return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

/** Compact relative-time label ("3m", "2h", "5d"). */
export function formatRelative(
  value: string | number | undefined | null,
): string {
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

export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return "Unexpected error";
}

/** Normalize list endpoints that may return a bare array or `{ items | data }`. */
export function asRecordArray(value: unknown): Record<string, unknown>[] {
  if (Array.isArray(value)) {
    return value.filter(
      (row): row is Record<string, unknown> =>
        typeof row === "object" && row !== null,
    );
  }
  if (typeof value === "object" && value !== null) {
    const obj = value as Record<string, unknown>;
    for (const key of ["items", "data", "approvals", "receipts", "decisions"]) {
      if (Array.isArray(obj[key])) {
        return asRecordArray(obj[key]);
      }
    }
  }
  return [];
}

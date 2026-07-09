/**
 * Resolve console time tokens to RFC3339 UTC for gateway filters.
 * Gateway /v1/soc/query only accepts parseable absolute timestamps for
 * filters.from / filters.to — relative tokens like `now-24h` must be
 * expanded client-side.
 */

const RELATIVE =
  /^now(?:-(\d+)([smhd]))?$/i;

/**
 * Convert `now`, `now-15m`, `now-24h`, `now-7d`, or pass through ISO/RFC3339.
 * Returns null if the token is unparseable.
 */
export function resolveTimeToken(
  token: string,
  nowMs: number = Date.now(),
): string | null {
  const trimmed = token.trim();
  if (!trimmed) return null;

  const rel = RELATIVE.exec(trimmed);
  if (rel) {
    const amount = rel[1] ? Number(rel[1]) : 0;
    const unit = (rel[2] ?? "s").toLowerCase();
    let deltaMs = 0;
    if (amount > 0) {
      switch (unit) {
        case "s":
          deltaMs = amount * 1_000;
          break;
        case "m":
          deltaMs = amount * 60_000;
          break;
        case "h":
          deltaMs = amount * 3_600_000;
          break;
        case "d":
          deltaMs = amount * 86_400_000;
          break;
        default:
          return null;
      }
    }
    return new Date(nowMs - deltaMs).toISOString();
  }

  // Absolute: accept Date-parseable strings (ISO 8601 / RFC3339).
  const abs = Date.parse(trimmed);
  if (Number.isFinite(abs)) {
    return new Date(abs).toISOString();
  }
  return null;
}

/** Resolve both ends of a range; omit invalid ends rather than sending junk. */
export function resolveTimeRange(range: {
  from: string;
  to: string;
}): { from?: string; to?: string } {
  const from = resolveTimeToken(range.from) ?? undefined;
  const to = resolveTimeToken(range.to) ?? undefined;
  return { from, to };
}

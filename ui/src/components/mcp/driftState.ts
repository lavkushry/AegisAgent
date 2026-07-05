import type { McpManifestSnapshot, McpServerRecord } from "@/app/api";

export type McpIntegrityStatus = "unknown" | "healthy" | "drifted" | "quarantined";

export function hasPinnedManifest(server: Pick<McpServerRecord, "manifest_hash">): boolean {
  return Boolean(server.manifest_hash?.trim());
}

export function snapshotsHaveDrift(snapshots: ReadonlyArray<McpManifestSnapshot>): boolean {
  if (snapshots.length < 2) return false;
  const hashes = snapshots.map((s) => s.manifest_hash?.trim() ?? "").filter(Boolean);
  return new Set(hashes).size > 1;
}

export function resolveMcpIntegrityStatus(
  server: McpServerRecord,
  snapshots: ReadonlyArray<McpManifestSnapshot> = [],
): McpIntegrityStatus {
  const status = String(server.status ?? "").toLowerCase();
  if (status === "quarantined") return "quarantined";
  if (!hasPinnedManifest(server)) return "unknown";

  const pinned = server.manifest_hash!.trim();
  const latest = snapshots[0]?.manifest_hash?.trim();
  if (latest && latest !== pinned) return "drifted";
  if (status === "drifted") return "drifted";
  if (snapshotsHaveDrift(snapshots)) return "drifted";

  return "healthy";
}

export function integrityStatusLabel(status: McpIntegrityStatus): string {
  switch (status) {
    case "healthy":
      return "Healthy";
    case "drifted":
      return "Drifted";
    case "quarantined":
      return "Quarantined";
    default:
      return "Unknown";
  }
}

export function integrityNeverHealthy(status: McpIntegrityStatus): boolean {
  return status === "unknown";
}
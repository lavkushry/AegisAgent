import type { McpManifestSnapshot } from "@/app/api";

export interface ManifestTimelineEntry {
  manifest_hash: string;
  created_at: string;
  event_type: "discovery" | "drift";
  description: string;
}

export function buildManifestTimeline(
  snapshots: ReadonlyArray<McpManifestSnapshot>,
): ManifestTimelineEntry[] {
  if (snapshots.length === 0) return [];

  return snapshots.map((snapshot, index) => {
    const hash = snapshot.manifest_hash?.trim() ?? "";
    const createdAt = snapshot.created_at ?? "";
    const older = snapshots[index + 1];
    const olderHash = older?.manifest_hash?.trim() ?? "";
    const isDrift = Boolean(olderHash && hash && hash !== olderHash);

    return {
      manifest_hash: hash,
      created_at: createdAt,
      event_type: isDrift ? "drift" : "discovery",
      description: isDrift
        ? `Manifest drift detected — hash changed from prior discovery.`
        : index === snapshots.length - 1
          ? "Initial manifest discovery pinned."
          : "Manifest discovery recorded.",
    };
  });
}
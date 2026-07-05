import { describe, expect, it } from "vitest";

import { buildManifestTimeline } from "./manifestHistory";

describe("buildManifestTimeline", () => {
  it("classifies hash changes as drift events", () => {
    const timeline = buildManifestTimeline([
      { manifest_hash: "sha256:new", created_at: "2026-07-05T12:00:00Z" },
      { manifest_hash: "sha256:old", created_at: "2026-07-04T12:00:00Z" },
    ]);
    expect(timeline[0]?.event_type).toBe("drift");
    expect(timeline[1]?.event_type).toBe("discovery");
  });

  it("returns empty for no snapshots", () => {
    expect(buildManifestTimeline([])).toEqual([]);
  });
});
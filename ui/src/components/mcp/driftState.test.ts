import { describe, expect, it } from "vitest";

import type { McpManifestSnapshot, McpServerRecord } from "@/app/api";
import {
  integrityStatusLabel,
  resolveMcpIntegrityStatus,
  snapshotsHaveDrift,
} from "./driftState";

const baseServer = (overrides: Partial<McpServerRecord> = {}): McpServerRecord => ({
  server_key: "github-mcp",
  status: "active",
  manifest_hash: "sha256:abc",
  ...overrides,
});

describe("resolveMcpIntegrityStatus", () => {
  it("never marks empty manifest as healthy", () => {
    expect(resolveMcpIntegrityStatus(baseServer({ manifest_hash: "" }), [])).toBe("unknown");
    expect(resolveMcpIntegrityStatus(baseServer({ manifest_hash: undefined }), [])).toBe("unknown");
  });

  it("marks quarantined servers regardless of hash", () => {
    expect(resolveMcpIntegrityStatus(baseServer({ status: "quarantined" }), [])).toBe("quarantined");
  });

  it("detects drift when latest snapshot differs from pinned hash", () => {
    const snapshots: McpManifestSnapshot[] = [
      { manifest_hash: "sha256:new", created_at: "2026-07-05T10:00:00Z" },
      { manifest_hash: "sha256:abc", created_at: "2026-07-04T10:00:00Z" },
    ];
    expect(resolveMcpIntegrityStatus(baseServer(), snapshots)).toBe("drifted");
  });

  it("marks pinned servers with stable history as healthy", () => {
    const snapshots: McpManifestSnapshot[] = [
      { manifest_hash: "sha256:abc", created_at: "2026-07-05T10:00:00Z" },
    ];
    expect(resolveMcpIntegrityStatus(baseServer(), snapshots)).toBe("healthy");
  });
});

describe("snapshotsHaveDrift", () => {
  it("returns false for a single snapshot", () => {
    expect(snapshotsHaveDrift([{ manifest_hash: "sha256:a" }])).toBe(false);
  });

  it("returns true when hashes differ", () => {
    expect(
      snapshotsHaveDrift([
        { manifest_hash: "sha256:a" },
        { manifest_hash: "sha256:b" },
      ]),
    ).toBe(true);
  });
});

describe("integrityStatusLabel", () => {
  it("maps unknown to Unknown label", () => {
    expect(integrityStatusLabel("unknown")).toBe("Unknown");
  });
});
import { describe, expect, it, vi, afterEach } from "vitest";

import * as api from "@/app/api";
import { discoverSettingsCapabilities } from "./capabilities";

const opts = {
  gatewayUrl: "http://127.0.0.1:8080",
  bearerToken: "token",
  tenantId: "tenant-a",
};

describe("discoverSettingsCapabilities", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("probes gateway endpoints for settings support", async () => {
    const probe = vi.spyOn(api, "probeGatewayEndpoint").mockResolvedValue(true);
    const caps = await discoverSettingsCapabilities(opts);
    expect(caps.webhooks).toBe(true);
    expect(caps.tenantDetail).toBe(true);
    expect(probe).toHaveBeenCalled();
  });
});
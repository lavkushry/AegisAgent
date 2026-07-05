import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import DetectionsPage from "./DetectionsPage";

vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ data: undefined, isLoading: false, error: null }),
}));

vi.mock("@/app/store", () => ({
  useAppStore: (selector?: (state: Record<string, unknown>) => unknown) => {
    const state = {
      gatewayUrl: "http://127.0.0.1:8080",
      bearerToken: "token",
      activeTenant: "tenant-a",
      authEpoch: 0,
    };
    return typeof selector === "function" ? selector(state) : state;
  },
}));

describe("DetectionsPage", () => {
  it("renders alerts-only detections chrome with redacted record label", () => {
    const html = renderToStaticMarkup(<DetectionsPage />);
    expect(html).toContain("Active Detections");
    expect(html).toContain("Triggered Detections Log");
    expect(html).toContain("redacted alert record");
    expect(html).not.toContain("Detection Rules");
    expect(html).not.toContain("Rules Catalogue");
  });
});
import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import ExploreTab from "./ExploreTab";

vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ data: undefined, isLoading: false, error: null, isFetching: false }),
  useMutation: () => ({ mutate: vi.fn(), isPending: false }),
}));

vi.mock("../app/store", () => ({
  useAppStore: (selector?: (state: Record<string, unknown>) => unknown) => {
    const state = {
      gatewayUrl: "http://127.0.0.1:8080",
      bearerToken: "token",
      activeTenant: "tenant-a",
      authEpoch: 0,
      exploreSeed: null,
      exploreQuery: "",
      consumeExploreSeed: vi.fn(),
      setExploreQuery: vi.fn(),
      timeRange: "24h",
    };
    return typeof selector === "function" ? selector(state) : state;
  },
}));

describe("ExploreTab", () => {
  it("renders production explore chrome without pre-verified receipt badges", () => {
    const html = renderToStaticMarkup(<ExploreTab />);
    expect(html).toContain("Explore / Discover");
    expect(html).toContain("Authorization Decisions");
    expect(html).toContain("Structured AQL filters");
    expect(html).not.toContain("Tamper-free");
    expect(html).not.toContain("text-green-400");
  });
});
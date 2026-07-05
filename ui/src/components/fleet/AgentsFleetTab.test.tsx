import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import AgentsFleetTab from "./AgentsFleetTab";

vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ data: [], isLoading: false, error: null }),
}));

vi.mock("@/app/store", () => ({
  useAppStore: (selector?: (state: Record<string, unknown>) => unknown) => {
    const state = {
      gatewayUrl: "http://127.0.0.1:8080",
      bearerToken: "token",
      activeTenant: "tenant-a",
      authEpoch: 0,
      activeAgentId: null,
      setActiveAgentId: vi.fn(),
    };
    return typeof selector === "function" ? selector(state) : state;
  },
}));

describe("AgentsFleetTab", () => {
  it("renders production fleet chrome with advisory risk labeling", () => {
    const html = renderToStaticMarkup(<AgentsFleetTab />);
    expect(html).toContain("Agents Fleet");
    expect(html).toContain("Advisory risk (24h)");
    expect(html).toContain("advisory only");
    expect(html).not.toContain("Tamper-free");
  });
});
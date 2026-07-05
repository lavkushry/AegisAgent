import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import McpTab from "./McpTab";

vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ data: undefined, isLoading: false, error: null }),
  useMutation: () => ({ mutate: vi.fn(), isPending: false }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
}));

vi.mock("@/hooks/useSessionRole", () => ({
  useEffectiveRole: () => ({ role: "admin", source: "override" }),
}));

vi.mock("@/app/store", () => ({
  useAppStore: (selector?: (state: Record<string, unknown>) => unknown) => {
    const state = {
      gatewayUrl: "http://127.0.0.1:8080",
      bearerToken: "token",
      activeTenant: "tenant-a",
      authEpoch: 0,
      setActiveView: vi.fn(),
    };
    return typeof selector === "function" ? selector(state) : state;
  },
}));

describe("McpTab", () => {
  it("renders MCP governance chrome with registry and unknown-never-healthy notice", () => {
    const html = renderToStaticMarkup(<McpTab />);
    expect(html).toContain("MCP Governance");
    expect(html).toContain("MCP Servers Registry");
    expect(html).toContain("never renders as healthy");
    expect(html).toContain("Select an MCP Server");
    expect(html).not.toMatch(/\bconfirm\s*\(/);
  });
});
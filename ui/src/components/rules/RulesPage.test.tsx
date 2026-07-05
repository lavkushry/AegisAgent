import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import RulesPage from "./RulesPage";

vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ data: undefined, isLoading: false, error: null }),
  useMutation: () => ({ mutate: vi.fn(), isPending: false }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
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

describe("RulesPage", () => {
  it("renders rules catalogue with deterministic and advisory-only notices", () => {
    const html = renderToStaticMarkup(<RulesPage />);
    expect(html).toContain("Detection Rules");
    expect(html).toContain("Rules Catalogue");
    expect(html).toContain("deterministically");
    expect(html).toContain("advisory-only");
    expect(html).toContain("historical backtesting");
    expect(html).not.toContain("Triggered Detections Log");
  });
});
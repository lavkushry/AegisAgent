import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import AlertingPage from "./AlertingPage";

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

describe("AlertingPage", () => {
  it("renders deterministic alerting sections", () => {
    const html = renderToStaticMarkup(<AlertingPage />);
    expect(html).toContain("Alerting");
    expect(html).toContain("Rule Health");
    expect(html).toContain("Contact Points");
    expect(html).toContain("Notification Policies");
    expect(html).toContain("Silences");
    expect(html).toContain("Active Response");
    expect(html).toContain("Secrets are redacted after creation");
    expect(html).not.toContain("super-secret");
  });
});
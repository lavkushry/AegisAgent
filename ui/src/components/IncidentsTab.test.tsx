import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import IncidentsTab from "./IncidentsTab";

vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ data: undefined, isLoading: false }),
  useMutation: () => ({ mutate: vi.fn(), isPending: false }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
}));

vi.mock("../app/store", () => ({
  useAppStore: (selector?: (state: Record<string, unknown>) => unknown) => {
    const state = {
      gatewayUrl: "http://127.0.0.1:8080",
      bearerToken: "token",
      activeTenant: "tenant-a",
      authEpoch: 0,
      activeIncidentId: null,
      setActiveIncidentId: vi.fn(),
    };
    return typeof selector === "function" ? selector(state) : state;
  },
}));

describe("IncidentsTab", () => {
  it("shows fail-closed timeline verification messaging before any chain proof runs", () => {
    const html = renderToStaticMarkup(<IncidentsTab />);
    expect(html).toContain("No Incident Selected");
    expect(html).not.toContain("Tamper-free");
    expect(html).not.toContain("text-green-400");
  });
});
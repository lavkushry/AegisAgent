import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import SettingsTab from "./SettingsTab";

vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ data: undefined, isLoading: false, error: null }),
}));

vi.mock("@/hooks/useSessionRole", () => ({
  useEffectiveRole: () => ({ role: "viewer", source: "session", operatorId: undefined }),
}));

vi.mock("@/app/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/app/store")>();
  return {
    ...actual,
    useAppStore: (selector?: (state: Record<string, unknown>) => unknown) => {
      const state = {
        gatewayUrl: "http://127.0.0.1:8080",
        bearerToken: "",
        activeTenant: "tenant-a",
        authEpoch: 0,
        theme: "dark-soc",
        density: "compact",
        role: "viewer",
        liveMode: false,
        redactByDefault: true,
        defaultLiveMode: false,
        setGatewayUrl: vi.fn(),
        setBearerToken: vi.fn(),
        setActiveTenant: vi.fn(),
        setTheme: vi.fn(),
        setDensity: vi.fn(),
        setRole: vi.fn(),
        setLiveMode: vi.fn(),
        setRedactByDefault: vi.fn(),
        setDefaultLiveMode: vi.fn(),
        setActiveView: vi.fn(),
      };
      return typeof selector === "function" ? selector(state) : state;
    },
  };
});

describe("SettingsTab", () => {
  it("renders capability-scoped settings sections with secret redaction notice", () => {
    const html = renderToStaticMarkup(<SettingsTab />);
    expect(html).toContain("Settings");
    expect(html).toContain("Gateway Connection");
    expect(html).toContain("RBAC Matrix");
    expect(html).toContain("Console Preferences");
    expect(html).toContain("Local only");
    expect(html).toContain("in-memory only");
    expect(html).toContain("Stored value:");
    expect(html).not.toMatch(/\bconfirm\s*\(/);
  });
});
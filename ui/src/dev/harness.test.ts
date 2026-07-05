import { describe, expect, it, vi } from "vitest";

import { DEV_HARNESS_ENABLED, DEV_HARNESS_VIEW } from "./guard";
import { HARNESS_SCENARIOS, HARNESS_TARGETS, scenariosForTarget } from "./scenarios";
import { CONSOLE_VIEWS } from "@/state/consoleUrl";
import { syntheticRedactedPayload } from "./fixtures";
import { redactJson } from "@/components/primitives/JsonViewer";

vi.mock("@/datasources/registry", () => ({
  useDatasources: () =>
    new Map([
      [
        "receipt",
        {
          id: "receipt",
          capabilities: { query: true, stream: false, fields: true, verify: true },
          verifyReceipt: vi.fn(),
          verifyRange: vi.fn(),
          exportEvidencePack: vi.fn(),
        },
      ],
    ]),
}));

describe("dev harness guard", () => {
  it("excludes the harness route from console views when disabled in production", () => {
    if (!DEV_HARNESS_ENABLED) {
      expect(CONSOLE_VIEWS).not.toContain(DEV_HARNESS_VIEW);
    } else {
      expect(CONSOLE_VIEWS).toContain(DEV_HARNESS_VIEW);
    }
  });

  it("never embeds secrets in synthetic fixtures", () => {
    const serialized = JSON.stringify(HARNESS_SCENARIOS);
    expect(serialized).not.toMatch(/sk-live|Bearer eyJ|password=|api_key=/i);
    const redacted = redactJson(syntheticRedactedPayload) as Record<string, unknown>;
    expect(redacted.api_token).toBe("[REDACTED]");
    expect((redacted.parameters as Record<string, unknown>).authorization).toBe("[REDACTED]");
  });
});

describe("harness scenario catalog", () => {
  it("covers every listed panel and primitive target", () => {
    for (const target of HARNESS_TARGETS) {
      expect(scenariosForTarget(target).length).toBeGreaterThan(0);
    }
  });

  it("includes security-sensitive states for review", () => {
    const states = new Set(HARNESS_SCENARIOS.map((scenario) => scenario.state));
    for (const required of [
      "success",
      "loading",
      "empty",
      "error",
      "tampered",
      "broken-row",
      "unknown-verification",
      "rbac-disabled",
      "redacted",
    ] as const) {
      expect(states.has(required)).toBe(true);
    }
  });

});
import { test, expect } from "../fixtures/guardedTest";
import { MOCK_TENANT_A } from "../fixtures/gatewayFixtures";
import {
  installMockGateway,
  openMockedConsole,
} from "../fixtures/installMockGateway";
import { openNav } from "./helpers";

/**
 * Mocked coverage for schema-driven panels shipped after the Bun rewrite
 * (timeseries, heatmap, agent-risk-map, decision-graph, receipt-integrity).
 * Uses Playwright route interception — no live gateway required.
 */
test.describe("mocked panel suite (charts + differentiators)", () => {
  test("Overview renders timeseries, heatmaps, and risk map from fixtures", async ({
    page,
  }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page, { tenantId: MOCK_TENANT_A });
    await openNav(page, "Overview");

    // Timeseries (soc-query count_over_time)
    const ts = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", { name: /Decisions over time/i }),
    });
    await expect(ts).toBeVisible({ timeout: 15_000 });
    await expect(ts.getByRole("img")).toBeVisible();
    await expect(ts.getByRole("img")).toHaveAttribute(
      "aria-label",
      /points|Decisions/i,
    );

    // Heatmap facets (count_by)
    await expect(
      page.getByRole("heading", { name: /By decision/i }),
    ).toBeVisible();
    const byDecision = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", { name: /^By decision$/i }),
    });
    await expect(byDecision.getByRole("img")).toBeVisible();
    await expect(byDecision.getByRole("img")).toHaveAttribute(
      "aria-label",
      /categories|By decision/i,
    );

    await expect(
      page.getByRole("heading", { name: /By source trust/i }),
    ).toBeVisible();

    // Agent risk map (scoreboard snapshot)
    const risk = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", {
        name: /Riskiest agents \(24h, advisory\)/i,
      }),
    });
    await expect(risk).toBeVisible({ timeout: 15_000 });
    await expect(risk.getByRole("img")).toBeVisible();
    await expect(risk.getByRole("img")).toHaveAttribute(
      "aria-label",
      /agents by 24h risk/i,
    );
    // Scoreboard fixture includes the mock agent key (may be truncated in SVG).
    await expect(risk.locator(`[data-testid="agent-risk-row"]`)).toHaveCount(
      3,
      { timeout: 10_000 },
    );

    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Dashboards preview of Incidents template shows decision-graph", async ({
    page,
  }) => {
    const mock = await installMockGateway(page, { role: "admin" });
    await openMockedConsole(page);
    await openNav(page, "Dashboards");

    // Copy system incidents board into the editor (aria-label: Copy incidents)
    await page.getByRole("button", { name: "Copy incidents" }).click();
    const editor = page.locator("textarea").first();
    await expect(editor).toBeVisible({ timeout: 5_000 });
    await expect(editor).toHaveValue(/decision-graph/, { timeout: 5_000 });

    await page.getByRole("button", { name: /^Preview$/i }).click();
    await expect(
      page.getByRole("heading", { name: /Evidence graph \(latest case\)/i }),
    ).toBeVisible({ timeout: 15_000 });

    const graph = page.getByTestId("decision-graph-panel");
    await expect(graph).toBeVisible({ timeout: 15_000 });
    await expect(graph.getByRole("img")).toBeVisible();
    await expect(graph.getByRole("img")).toHaveAttribute(
      "aria-label",
      /Evidence graph|nodes/i,
    );

    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Dashboards preview of Integrity template shows chain controls", async ({
    page,
  }) => {
    const mock = await installMockGateway(page, {
      role: "viewer",
      receiptVerifyMode: "verified",
    });
    await openMockedConsole(page);
    await openNav(page, "Dashboards");

    await page.getByRole("button", { name: "Copy integrity" }).click();
    await page.getByRole("button", { name: /^Preview$/i }).click();

    await expect(
      page.getByRole("heading", { name: /Verify & export/i }),
    ).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId("receipt-integrity-panel")).toBeVisible();
    await expect(
      page.getByRole("button", { name: /Verify range/i }),
    ).toBeVisible();

    await page.getByRole("button", { name: /Verify range/i }).click();
    await expect(
      page.getByText(/tamper-free|matches recomputed|verified|Walking/i).first(),
    ).toBeVisible({ timeout: 10_000 });

    await expect(
      page.getByRole("heading", { name: /Hash-chained receipts/i }),
    ).toBeVisible();

    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Dashboards preview of Fleet template shows risk scoreboard map", async ({
    page,
  }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page);
    await openNav(page, "Dashboards");

    await page.getByRole("button", { name: "Copy fleet" }).click();
    await page.getByRole("button", { name: /^Preview$/i }).click();

    const risk = page.locator("section.panel-card").filter({
      has: page.getByRole("heading", {
        name: /24h composite risk \(advisory\)/i,
      }),
    });
    await expect(risk).toBeVisible({ timeout: 15_000 });
    await expect(risk.getByRole("img")).toBeVisible();
    await expect(risk.locator(`[data-testid="agent-risk-row"]`)).toHaveCount(
      3,
      { timeout: 10_000 },
    );

    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });
});

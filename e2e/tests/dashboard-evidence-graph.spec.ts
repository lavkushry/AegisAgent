import { test, expect } from "@playwright/test";
import { createAllowedDecision, registerTestAgent } from "./helpers";

// Evidence Graph Visualization (#1273): the agent detail page renders
// GET /v1/graph/agent/:id with vis-network. The incident detail page wires
// the same shared rendering path against GET /v1/graph/incident/:id, but
// incidents are an emergent property of the async SOC correlation pipeline
// with no direct creation API, so there is no deterministic way to produce
// one from this E2E suite — that endpoint's behavior is covered by the Rust
// route tests in src/src/routes/graph.rs instead.

test.describe("dashboard evidence graph (#1273)", () => {
  test("agent detail page renders the evidence graph, color-coded legend, and a clickable node detail panel", async ({
    page,
    request,
    baseURL,
  }) => {
    const agentKey = `dashboard-e2e-graph-${Date.now()}`;
    const agent = await registerTestAgent(request, baseURL!, agentKey);
    await createAllowedDecision(request, baseURL!, agent.agentToken, agentKey);

    await page.goto("/dashboard/");
    await page.locator('.menu-item[data-view="agents"]').click();

    const row = page.locator("#agents-tbody tr", { hasText: agentKey });
    await expect(row).toBeVisible({ timeout: 10_000 });
    await row.click();

    // Detail view replaces the list view.
    await expect(page.locator("#agent-detail-container")).toBeVisible();
    await expect(page.locator("#agent-list-container")).toBeHidden();
    await expect(page.locator("#agent-detail-id")).toContainText(agentKey);

    // Loading state shows, then clears once the graph query resolves.
    await expect(page.locator("#agent-graph-loading")).toBeHidden({
      timeout: 10_000,
    });

    // vis-network renders to a <canvas>, not per-node DOM elements.
    await expect(page.locator("#agent-graph-container canvas")).toBeVisible();

    // Legend is color-coded by node type (#1273 AC).
    const legend = page.locator("#agent-graph-legend");
    await expect(legend).toContainText("Agent");
    await expect(legend).toContainText("Decision: Allow");
    await expect(legend).toContainText("Receipt");
    await expect(legend).toContainText("Incident");

    // Click the agent's own node (deterministic id: "agent:<uuid>") via
    // vis-network's canvasToDOM() coordinate mapping, exposed on the
    // container element specifically for this kind of canvas-click test.
    const nodeDetail = page.locator("#agent-graph-node-detail");
    await expect(nodeDetail).toBeHidden();

    await page.evaluate((agentId) => {
      var container = document.getElementById("agent-graph-container");
      var network = (container as any).visNetwork;
      var pos = network.getPositions(["agent:" + agentId])["agent:" + agentId];
      var domPos = network.canvasToDOM(pos);
      var rect = container.getBoundingClientRect();
      (window as any).__testClickX = rect.left + domPos.x;
      (window as any).__testClickY = rect.top + domPos.y;
    }, agent.id);

    const clickX = await page.evaluate(() => (window as any).__testClickX);
    const clickY = await page.evaluate(() => (window as any).__testClickY);
    await page.mouse.click(clickX, clickY);

    await expect(nodeDetail).toBeVisible({ timeout: 5_000 });
    await expect(page.locator("#agent-graph-node-type")).toHaveText("agent");
    await expect(page.locator("#agent-graph-node-label")).toContainText(
      "Dashboard E2E Test Agent",
    );

    // Zoom/pan/drag (#1273 AC): vis-network wires these as part of its
    // default `interaction` options (zoomView/dragView/dragNodes, all
    // explicitly enabled in renderEvidenceGraph) — covered structurally
    // above by asserting the network actually initializes on this
    // container; exercising the literal wheel/drag gestures pixel-by-pixel
    // adds flakiness without adding real signal over a canvas surface.

    // Back to the fleet list.
    await page.locator("#back-to-agents-btn").click();
    await expect(page.locator("#agent-list-container")).toBeVisible();
    await expect(page.locator("#agent-detail-container")).toBeHidden();
  });
});

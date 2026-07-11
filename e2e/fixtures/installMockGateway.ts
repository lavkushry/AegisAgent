import type { Page, Route } from "@playwright/test";
import {
  createMockRuntimeState,
  FAKE_BEARER,
  MOCK_TENANT_A,
  resolveMockResponse,
  type MockRuntimeState,
  type MockScenario,
} from "./gatewayFixtures";

export const MOCK_GATEWAY_ORIGIN = "http://127.0.0.1:8080";

export interface MockGatewayHandle {
  unhandled: string[];
  runtime: MockRuntimeState;
  dispose: () => Promise<void>;
}

/**
 * Route `/v1/**` (and optional liveness) to deterministic fixtures.
 * Targets the Bun SPA (`ui-next`) served at `/dashboard/`.
 */
export async function installMockGateway(
  page: Page,
  scenario: MockScenario = {},
): Promise<MockGatewayHandle> {
  const unhandled: string[] = [];
  const runtime = createMockRuntimeState();
  const v1Pattern = `${MOCK_GATEWAY_ORIGIN}/v1/**`;
  const livezPattern = `${MOCK_GATEWAY_ORIGIN}/livez`;

  const v1Handler = async (route: Route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    const tenantHeader = request.headers()["x-aegis-tenant-id"];
    const tenantId = tenantHeader || scenario.tenantId || MOCK_TENANT_A;
    let body: unknown;
    try {
      body = request.postDataJSON();
    } catch {
      body = undefined;
    }

    const resolved = resolveMockResponse(
      request.method(),
      path,
      tenantId,
      scenario,
      runtime,
      body,
      url.search,
    );
    if (!resolved) {
      unhandled.push(`${request.method()} ${path}`);
      await route.fulfill({
        status: 501,
        contentType: "application/json",
        body: JSON.stringify({
          error: `Unhandled mock route: ${request.method()} ${path}`,
        }),
      });
      return;
    }

    await route.fulfill({
      status: resolved.status,
      contentType: "application/json",
      body: JSON.stringify(resolved.body),
    });
  };

  const livezHandler = async (route: Route) => {
    await route.fulfill({
      status: 200,
      contentType: "text/plain",
      body: "ok",
    });
  };

  await page.route(v1Pattern, v1Handler);
  await page.route(livezPattern, livezHandler);

  return {
    unhandled,
    runtime,
    dispose: async () => {
      await page.unroute(v1Pattern, v1Handler);
      await page.unroute(livezPattern, livezHandler);
    },
  };
}

/**
 * Configure ui-next Settings (connection form lives only on `/dashboard/settings`).
 * Optionally set Operator ID for approval mutations.
 */
export async function openMockedConsole(
  page: Page,
  scenario: MockScenario = {},
): Promise<void> {
  const tenantId = scenario.tenantId ?? MOCK_TENANT_A;
  const operatorId = scenario.operatorId ?? "e2e_operator";

  await page.goto("/dashboard/settings");
  await page.getByLabel(/Gateway URL/i).fill(MOCK_GATEWAY_ORIGIN);
  await page.getByLabel(/Tenant ID/i).fill(tenantId);
  await page.getByLabel(/Bearer token/i).fill(FAKE_BEARER);
  const operator = page.getByLabel(/Operator ID/i);
  if ((await operator.count()) > 0) {
    await operator.fill(operatorId);
  }
  await page.getByRole("button", { name: /Apply Config/i }).click();
  await page.getByText(tenantId, { exact: true }).first().waitFor();
}

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

export async function installMockGateway(
  page: Page,
  scenario: MockScenario = {},
): Promise<MockGatewayHandle> {
  const unhandled: string[] = [];
  const runtime = createMockRuntimeState();
  const pattern = `${MOCK_GATEWAY_ORIGIN}/v1/**`;

  const handler = async (route: Route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    const tenantHeader = request.headers()["x-aegis-tenant-id"];
    const tenantId = tenantHeader || scenario.tenantId || MOCK_TENANT_A;

    const resolved = resolveMockResponse(request.method(), path, tenantId, scenario, runtime);
    if (!resolved) {
      unhandled.push(`${request.method()} ${path}`);
      await route.fulfill({
        status: 501,
        contentType: "application/json",
        body: JSON.stringify({ error: `Unhandled mock route: ${request.method()} ${path}` }),
      });
      return;
    }

    await route.fulfill({
      status: resolved.status,
      contentType: "application/json",
      body: JSON.stringify(resolved.body),
    });
  };

  await page.route(pattern, handler);

  return {
    unhandled,
    runtime,
    dispose: async () => {
      await page.unroute(pattern, handler);
    },
  };
}

export async function openMockedConsole(page: Page, scenario: MockScenario = {}): Promise<void> {
  const tenantId = scenario.tenantId ?? MOCK_TENANT_A;
  await page.goto("/dashboard/");
  await page.getByLabel("Gateway URL").fill(MOCK_GATEWAY_ORIGIN);
  await page.getByLabel("Bearer Token").fill(FAKE_BEARER);
  await page.getByLabel("Tenant ID").fill(tenantId);
  await page.getByRole("button", { name: "Apply Config" }).click();
  await page.getByText(tenantId, { exact: true }).first().waitFor();
}
import type { FetchOptions } from "@/app/api";
import { probeGatewayEndpoint } from "@/app/api";

export interface SettingsCapabilities {
  session: boolean;
  tenantDetail: boolean;
  riskWeights: boolean;
  webhooks: boolean;
  silences: boolean;
  retentionConfig: boolean;
}

export async function discoverSettingsCapabilities(
  opts: FetchOptions,
): Promise<SettingsCapabilities> {
  const [session, tenantDetail, riskWeights, webhooks, silences, retentionConfig] =
    await Promise.all([
      probeGatewayEndpoint(opts, "/v1/session"),
      opts.tenantId
        ? probeGatewayEndpoint(opts, `/v1/tenants/${encodeURIComponent(opts.tenantId)}`)
        : Promise.resolve(false),
      probeGatewayEndpoint(opts, "/v1/tenants/risk-weights"),
      probeGatewayEndpoint(opts, "/v1/webhook_subscriptions?limit=1"),
      probeGatewayEndpoint(opts, "/v1/soc/silences?limit=1"),
      probeGatewayEndpoint(opts, "/v1/admin/retention"),
    ]);

  return {
    session,
    tenantDetail,
    riskWeights,
    webhooks,
    silences,
    retentionConfig,
  };
}
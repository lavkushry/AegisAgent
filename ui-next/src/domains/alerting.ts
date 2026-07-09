import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface WebhookSubscriptionRecord {
  id: string;
  url: string;
  event_types?: string;
  status?: string;
  min_severity?: string;
  format?: string;
  delivery_status?: string;
  consecutive_failures?: number;
  last_delivery_at?: string | null;
  last_success_at?: string | null;
  created_at?: string;
}

export function listWebhookSubscriptions(
  opts: FetchOptions,
  limit = 50,
): Promise<WebhookSubscriptionRecord[]> {
  return fetchFromGateway<unknown>(
    opts,
    `/v1/webhook_subscriptions?limit=${limit}`,
  ).then((raw) =>
    asRecordArray(raw).map((r) => r as unknown as WebhookSubscriptionRecord),
  );
}

export function reactivateWebhook(
  opts: FetchOptions,
  id: string,
): Promise<WebhookSubscriptionRecord> {
  return fetchFromGateway(
    opts,
    `/v1/webhook_subscriptions/${encodeURIComponent(id)}/reactivate`,
    "POST",
    {},
  );
}

/** Redact secrets from URL query for display. */
export function redactUrl(url: string | undefined): string {
  if (!url) return "—";
  try {
    const u = new URL(url);
    u.search = "";
    u.hash = "";
    return u.toString();
  } catch {
    return url.replace(/([?&](token|secret|key)=)[^&]*/gi, "$1***");
  }
}

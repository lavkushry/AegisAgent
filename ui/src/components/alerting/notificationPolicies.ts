import type { WebhookSubscriptionRecord } from "@/app/api";
import { classifyWebhookUrl } from "./supportStates";

export interface NotificationPolicyRow {
  id: string;
  label: string;
  channel: string;
  eventTypes: string;
  minSeverity: string;
  deliveryStatus: string;
  status: string;
}

export function buildNotificationPolicies(
  subscriptions: ReadonlyArray<WebhookSubscriptionRecord>,
): NotificationPolicyRow[] {
  return subscriptions.map((sub) => {
    const channel = classifyWebhookUrl(sub.url);
    return {
      id: sub.id,
      label: `${channel} → ${sub.event_types}`,
      channel,
      eventTypes: sub.event_types,
      minSeverity: sub.min_severity,
      deliveryStatus: sub.delivery_status,
      status: sub.status,
    };
  });
}
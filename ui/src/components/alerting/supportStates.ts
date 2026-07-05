import type { WebhookSubscriptionRecord } from "@/app/api";

export type ContactChannel = "slack" | "webhook" | "pagerduty" | "email";

export type ChannelSupport = "supported" | "standby" | "unsupported";

export interface AlertingBackendSupport {
  webhooks: boolean;
  playbooks: boolean;
  silences: boolean;
}

export interface ContactChannelStatus {
  channel: ContactChannel;
  support: ChannelSupport;
  detail: string;
}

export function classifyWebhookUrl(url: string): ContactChannel {
  const lower = url.toLowerCase();
  if (lower.includes("hooks.slack.com")) return "slack";
  if (lower.includes("events.pagerduty.com")) return "pagerduty";
  if (lower.startsWith("mailto:")) return "email";
  return "webhook";
}

export function contactChannelStatuses(
  backend: AlertingBackendSupport,
  subscriptions: ReadonlyArray<WebhookSubscriptionRecord>,
): ContactChannelStatus[] {
  const channels = new Set(subscriptions.map((sub) => classifyWebhookUrl(sub.url)));
  return [
    {
      channel: "slack",
      support: backend.webhooks && channels.has("slack") ? "supported" : backend.webhooks ? "standby" : "unsupported",
      detail: backend.webhooks
        ? channels.has("slack")
          ? "Slack incoming webhook subscriptions are registered."
          : "Route alerts via a Slack incoming webhook URL."
        : "Webhook subscriptions API unavailable on this gateway.",
    },
    {
      channel: "webhook",
      support: backend.webhooks ? "supported" : "unsupported",
      detail: backend.webhooks
        ? "Tenant-scoped HTTPS webhook subscriptions with signed delivery."
        : "Webhook subscriptions API unavailable on this gateway.",
    },
    {
      channel: "pagerduty",
      support: "standby",
      detail: "PagerDuty Events API routing is not exposed as a first-class contact point yet.",
    },
    {
      channel: "email",
      support: "unsupported",
      detail: "SMTP/email contact points require a gateway alerting settings API (not available).",
    },
  ];
}
-- TASK-0092 (#938): tenant-managed webhook subscriptions, registered via the
-- management API (`/v1/webhook_subscriptions`) so operators can receive SOC
-- notifications (alerts/incidents) at their own endpoints without an
-- `AEGIS_WEBHOOK_URL` redeploy. Mirrors the approval-callback secret-handling
-- pattern: only `sha256(secret)` is stored, never the plaintext secret.
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  url TEXT NOT NULL,
  secret_hash TEXT,
  event_types TEXT NOT NULL DEFAULT '*',
  status TEXT NOT NULL DEFAULT 'active',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_tenant
  ON webhook_subscriptions(tenant_id);

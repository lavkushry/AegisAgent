-- #1285: configurable webhook export (generic SIEM) — adds real delivery on
-- top of the TASK-0092 (#938) CRUD scaffold, which only ever stored
-- `secret_hash` (a one-way hash, useless for the gateway to sign outbound
-- deliveries with) and never actually dispatched anything.
--
-- `delivery_secret` is a NEW, separate, server-generated plaintext secret
-- (returned once at creation, like `agent_token`) used solely to HMAC-sign
-- outbound deliveries — analogous to `agents.signing_key`, which is also
-- stored in recoverable form because the gateway must reproduce the same
-- HMAC on every use. It is unrelated to the legacy `secret`/`secret_hash`
-- pair, which an operator could already set for some other out-of-band
-- purpose and which this migration leaves untouched.
ALTER TABLE webhook_subscriptions ADD COLUMN delivery_secret TEXT;
ALTER TABLE webhook_subscriptions ADD COLUMN min_severity TEXT NOT NULL DEFAULT 'info';
ALTER TABLE webhook_subscriptions ADD COLUMN format TEXT NOT NULL DEFAULT 'json';
-- Separate from the legacy `status` column (which TASK-0092 always set to
-- 'active' and nothing else ever read or wrote) to avoid changing that
-- column's established meaning out from under existing callers/tests.
ALTER TABLE webhook_subscriptions ADD COLUMN delivery_status TEXT NOT NULL DEFAULT 'healthy';
ALTER TABLE webhook_subscriptions ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE webhook_subscriptions ADD COLUMN last_delivery_at DATETIME;
ALTER TABLE webhook_subscriptions ADD COLUMN last_success_at DATETIME;

-- #1295: per-tenant toggle for auto-rotating an agent's token when an
-- external leak-detection signal is reported via
-- `POST /v1/agents/:id/report-leaked-token`. Defaults to enabled (1) so
-- existing tenants get the safer fail-closed-on-leak behavior automatically.
ALTER TABLE tenants ADD COLUMN auto_rotate_token_on_leak_enabled INTEGER NOT NULL DEFAULT 1;

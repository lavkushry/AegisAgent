-- #1193: soft-delete for policies and mcp_servers. DELETE endpoints mark
-- `deleted_at` instead of removing the row, so list/get queries can filter
-- it back out while the data stays recoverable; GDPR tenant erasure
-- (`DELETE /v1/tenants/:id`) is unaffected — it already issues a real
-- `DELETE FROM ...` regardless of this column.
--
-- `agents` already has equivalent soft-delete semantics via its existing
-- `status = 'deleted'` enum value (see `get_agent_by_id`/`list_agents`), so
-- it isn't touched here. `skills` has no user-facing delete operation at
-- all — rows are an internal auto-populated registry of tool calls an agent
-- has made, not a resource a user creates or deletes via an API — so there
-- is nothing to soft-delete there.
ALTER TABLE policies ADD COLUMN deleted_at DATETIME;
ALTER TABLE mcp_servers ADD COLUMN deleted_at DATETIME;

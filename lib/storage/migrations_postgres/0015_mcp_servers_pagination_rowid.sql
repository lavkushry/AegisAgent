-- #1142: explicit monotonic rowid for cursor pagination on mcp_servers.
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS rowid BIGSERIAL UNIQUE;
-- DB-007 (#932): track when each MCP server's tool manifest was last
-- (re-)discovered via POST /v1/mcp/servers/:server_key/tools, so operators
-- can see staleness alongside the pinned manifest_hash.
ALTER TABLE mcp_servers ADD COLUMN last_discovery_at DATETIME;

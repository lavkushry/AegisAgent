-- #1310: agent-to-gateway mTLS authentication. Maps a client certificate's
-- Subject CN to an agent within a tenant, as an alternative to bearer-token
-- auth. NULL = mTLS not bound for this agent (backwards-compatible; bearer
-- token auth remains the only path). Unique per tenant (partial index, since
-- SQLite would otherwise just let multiple NULLs through anyway) so a CN
-- can't ambiguously resolve to more than one agent.
ALTER TABLE agents ADD COLUMN mtls_cn TEXT;
CREATE UNIQUE INDEX idx_agents_tenant_mtls_cn ON agents(tenant_id, mtls_cn) WHERE mtls_cn IS NOT NULL;

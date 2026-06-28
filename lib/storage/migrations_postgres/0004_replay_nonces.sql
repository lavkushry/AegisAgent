-- PR8: durable, multi-instance-safe replay-nonce store (see the SQLite
-- 0025 migration). Shared (tenant, agent, nonce) dedup when AEGIS_REPLAY_STORE=db.
CREATE TABLE IF NOT EXISTS replay_nonces (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_replay_nonces_expires_at ON replay_nonces(expires_at);

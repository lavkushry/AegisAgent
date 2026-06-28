-- PR8: durable, multi-instance-safe replay-nonce store. The in-memory
-- ReplayNonceCache is per-process, so a replay can slip through after a restart
-- or against a second gateway instance. This table makes the (tenant, agent,
-- nonce) dedup shared and durable when AEGIS_REPLAY_STORE=db. The composite
-- primary key is the dedup constraint; expires_at bounds the window and lets a
-- cleanup job (and the inline expired-row refresh) reclaim space.
CREATE TABLE IF NOT EXISTS replay_nonces (
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_replay_nonces_expires_at ON replay_nonces(expires_at);

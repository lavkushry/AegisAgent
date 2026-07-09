-- Phase 8.3 (investigation evidence export): receipt chain checkpoints.
-- Postgres mirror of SQLite 0044_receipt_checkpoints.sql.
CREATE TABLE IF NOT EXISTS receipt_checkpoints (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    sequence_start BIGINT NOT NULL,
    sequence_end BIGINT NOT NULL,
    chain_head_hash TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    receipt_count BIGINT NOT NULL,
    signature TEXT,
    signer_key_id TEXT,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipt_checkpoints_tenant_created
    ON receipt_checkpoints(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_receipt_checkpoints_tenant_range
    ON receipt_checkpoints(tenant_id, sequence_start, sequence_end);

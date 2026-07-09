-- Phase 8.3 (investigation evidence export): receipt chain checkpoints.
-- A checkpoint commits a contiguous range of the tenant's hash-chained
-- action receipts to a Merkle root + chain-head hash so an evidence pack
-- can prove the range without re-walking the full chain. Tenant-scoped.
CREATE TABLE IF NOT EXISTS receipt_checkpoints (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    sequence_start INTEGER NOT NULL,
    sequence_end INTEGER NOT NULL,
    chain_head_hash TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    receipt_count INTEGER NOT NULL,
    signature TEXT,
    signer_key_id TEXT,
    created_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipt_checkpoints_tenant_created
    ON receipt_checkpoints(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_receipt_checkpoints_tenant_range
    ON receipt_checkpoints(tenant_id, sequence_start, sequence_end);

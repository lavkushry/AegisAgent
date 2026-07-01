-- Phase 2.3 (runtime control plane): signed gateway->sensor control commands
-- (start/pause/kill/quarantine/ban/freeze/revoke/block/disable/...). The
-- gateway persists the issued command; the sensor verifies the signature,
-- tenant binding, expiry, and nonce before executing idempotently and ACKing.
-- `(tenant_id, nonce)` is unique for replay protection. `signature` is over the
-- canonical command bytes (see AegisAgent_Control_Command_Protocol.md). No raw
-- secrets are stored here.
CREATE TABLE IF NOT EXISTS control_commands (
    command_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT,
    issued_by TEXT NOT NULL,
    issued_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    nonce TEXT NOT NULL,
    requires_ack INTEGER NOT NULL DEFAULT 1,
    receipt_required INTEGER NOT NULL DEFAULT 1,
    signature TEXT NOT NULL,
    -- issued | delivered | acked | nacked | executed | expired
    status TEXT NOT NULL DEFAULT 'issued',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_control_commands_tenant_nonce ON control_commands(tenant_id, nonce);
CREATE INDEX IF NOT EXISTS idx_control_commands_tenant_target ON control_commands(tenant_id, target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_control_commands_tenant_status ON control_commands(tenant_id, status);

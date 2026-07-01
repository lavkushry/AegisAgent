-- Phase 2.3 (runtime control plane): signed gateway->sensor control commands.
-- See the SQLite 0028 migration. `(tenant_id, nonce)` unique = replay protection.
CREATE TABLE IF NOT EXISTS control_commands (
    command_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT,
    issued_by TEXT NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    nonce TEXT NOT NULL,
    requires_ack BOOLEAN NOT NULL DEFAULT TRUE,
    receipt_required BOOLEAN NOT NULL DEFAULT TRUE,
    signature TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'issued',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_control_commands_tenant_nonce ON control_commands(tenant_id, nonce);
CREATE INDEX IF NOT EXISTS idx_control_commands_tenant_target ON control_commands(tenant_id, target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_control_commands_tenant_status ON control_commands(tenant_id, status);

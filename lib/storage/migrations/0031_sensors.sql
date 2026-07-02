-- Phase 3.2 (Agent Cage / aegis-node-sensor): registered runtime sensors.
-- `node_key` is the sensor's own stable per-host identifier (survives
-- restarts); re-registering with the same (tenant_id, node_key) updates the
-- existing row rather than creating a duplicate. `public_key` is the
-- sensor's Ed25519 identity key (hex), used to verify signed ACK/NACK
-- results in a later phase. Tenant-scoped.
CREATE TABLE IF NOT EXISTS sensors (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    node_key TEXT NOT NULL,
    hostname TEXT NOT NULL,
    environment TEXT,
    sensor_version TEXT NOT NULL,
    public_key TEXT NOT NULL,
    capabilities TEXT NOT NULL DEFAULT '[]',
    mode TEXT NOT NULL DEFAULT 'observe',
    -- registered | heartbeating | degraded | lockdown | draining
    status TEXT NOT NULL DEFAULT 'registered',
    config_version INTEGER NOT NULL DEFAULT 1,
    queue_depth_critical INTEGER,
    queue_depth_normal INTEGER,
    disk_usage_bytes INTEGER,
    active_cage_runs INTEGER,
    last_event_watermark TEXT,
    last_command_watermark TEXT,
    health_status TEXT,
    registered_at DATETIME NOT NULL,
    last_heartbeat_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sensors_tenant_id ON sensors(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sensors_tenant_node_key ON sensors(tenant_id, node_key);

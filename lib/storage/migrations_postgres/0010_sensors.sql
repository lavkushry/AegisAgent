-- Phase 3.2 (Agent Cage / aegis-node-sensor): registered runtime sensors.
-- See the SQLite 0031 migration.
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
    status TEXT NOT NULL DEFAULT 'registered',
    config_version INTEGER NOT NULL DEFAULT 1,
    queue_depth_critical BIGINT,
    queue_depth_normal BIGINT,
    disk_usage_bytes BIGINT,
    active_cage_runs BIGINT,
    last_event_watermark TEXT,
    last_command_watermark TEXT,
    health_status TEXT,
    registered_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_heartbeat_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sensors_tenant_id ON sensors(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sensors_tenant_node_key ON sensors(tenant_id, node_key);

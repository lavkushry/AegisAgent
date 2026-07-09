-- See lib/storage/migrations/0044_agent_run_cage_execution.sql for full
-- rationale. Kept in lockstep across both migration directories.
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS claimed_by TEXT;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS image_ref TEXT;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS image_digest TEXT;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS command_json TEXT;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS working_dir TEXT;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS resource_limits_json TEXT;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS network_spec_json TEXT;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS tooling_spec_json TEXT;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS environment_json TEXT;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS workspace_spec_json TEXT;
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS controlled_mounts_json TEXT;

CREATE INDEX IF NOT EXISTS idx_agent_runs_tenant_status ON agent_runs(tenant_id, status);

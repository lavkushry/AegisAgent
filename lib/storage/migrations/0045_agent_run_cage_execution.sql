-- Gives aegis-cage-runner (previously a lib-only crate with no execution
-- loop) an atomic claim mechanism and the full SandboxSpec fields it needs
-- to actually execute a run: agent_runs.status was write-once ("started"
-- at creation, never transitioned) with no way for a runner to
-- exclusively claim a row, and no columns to reconstruct a SandboxSpec
-- from.
--
-- claimed_by/claimed_at/last_heartbeat_at: back the claim CAS
-- (`UPDATE ... WHERE status = 'started'`) and the lease-expiry stall
-- sweep (mirrors the existing delete_expired_replay_nonces global-sweep
-- precedent). All NULL for every pre-existing/non-cage run.
--
-- image_ref .. controlled_mounts_json: mirror aegis_cage_runner::spec::
-- SandboxSpec's nested shapes, populated only when a caller opts in via
-- CreateAgentRunRequest.cage_spec (NULL otherwise -- the existing,
-- unaffected SDK-integrated-run case). *_json TEXT for the nested
-- shapes follows this schema's existing convention (manifest_json,
-- steps_json, settings_json, etc.) rather than a new one.
ALTER TABLE agent_runs ADD COLUMN claimed_by TEXT;
ALTER TABLE agent_runs ADD COLUMN claimed_at DATETIME;
ALTER TABLE agent_runs ADD COLUMN last_heartbeat_at DATETIME;
ALTER TABLE agent_runs ADD COLUMN image_ref TEXT;
ALTER TABLE agent_runs ADD COLUMN image_digest TEXT;
ALTER TABLE agent_runs ADD COLUMN command_json TEXT;
ALTER TABLE agent_runs ADD COLUMN working_dir TEXT;
ALTER TABLE agent_runs ADD COLUMN resource_limits_json TEXT;
ALTER TABLE agent_runs ADD COLUMN network_spec_json TEXT;
ALTER TABLE agent_runs ADD COLUMN tooling_spec_json TEXT;
ALTER TABLE agent_runs ADD COLUMN environment_json TEXT;
ALTER TABLE agent_runs ADD COLUMN workspace_spec_json TEXT;
ALTER TABLE agent_runs ADD COLUMN controlled_mounts_json TEXT;

CREATE INDEX IF NOT EXISTS idx_agent_runs_tenant_status ON agent_runs(tenant_id, status);

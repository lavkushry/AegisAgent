-- Runner-reported process/container exit code for cage (and other) runs.
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS exit_code INTEGER;

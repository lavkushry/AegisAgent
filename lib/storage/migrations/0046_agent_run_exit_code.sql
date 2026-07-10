-- Runner-reported process/container exit code for cage (and other) runs.
-- NULL until a runner reports a terminal status with an exit code.
ALTER TABLE agent_runs ADD COLUMN exit_code INTEGER;

-- Restrict agents to specific environments (#1391).
-- NULL = no restriction (all environments permitted, backwards-compatible).
ALTER TABLE agents ADD COLUMN allowed_environments TEXT;

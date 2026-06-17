-- #1293: trust propagation across agent chains.
-- root_trust_level records the most-restrictive (tighten-only) trust level
-- accumulated across the call chain up to and including this decision.
-- parent_run_id links this decision's run to the run that triggered it,
-- enabling reconstruction of multi-hop agent chains (A -> B -> C) for audit.
-- Both NULL for decisions that are not part of a chain (backwards compatible).
ALTER TABLE decisions ADD COLUMN root_trust_level TEXT;
ALTER TABLE decisions ADD COLUMN parent_run_id TEXT;

-- #approval-edit-lifecycle: editing a pending approval re-binds it to the
-- edited action's hash while PRESERVING the agent's original action hash, and
-- the approval stays pending (status='created') so it remains listed and
-- approvable. `original_call_hash` keeps the original; this column holds the
-- edited action's hash. The effective hash an approve/consume binds to is
-- COALESCE(effective_call_hash, original_call_hash). NULL = not edited.
--
-- Shipped as a forward migration (not an in-place edit of 0001_baseline) so
-- existing installs keep a stable _sqlx_migrations checksum for 0001.
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS effective_call_hash TEXT;

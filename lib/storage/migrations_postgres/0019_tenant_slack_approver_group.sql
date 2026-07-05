-- #1277: per-tenant Slack approver group for interactive approval callbacks.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS slack_approver_group TEXT;
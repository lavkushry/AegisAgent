-- #1277: per-tenant Slack approver group for interactive approval callbacks.
-- NULL/empty = any Slack user may approve (channel-member fallback).
-- Comma-separated Slack user IDs (U…) = static allowlist.
-- Slack usergroup ID (S…) = membership checked via Slack API when
-- AEGIS_SLACK_BOT_TOKEN is configured.
ALTER TABLE tenants ADD COLUMN slack_approver_group TEXT;
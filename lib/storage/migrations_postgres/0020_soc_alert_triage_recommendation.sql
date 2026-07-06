-- #1393: advisory triage recommendations for SOC alerts (sandboxed agent output).
ALTER TABLE soc_alerts ADD COLUMN IF NOT EXISTS triage_recommendation TEXT;
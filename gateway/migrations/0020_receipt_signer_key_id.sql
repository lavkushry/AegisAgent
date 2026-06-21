-- #1211: optional human-readable identifier for the Ed25519 key that signed
-- this receipt (parsed from an optional "key_id:" prefix on
-- AEGIS_RECEIPT_SIGNING_KEY), so an auditor can tell which generation of key
-- was active without having to recognize a raw public-key hex string.
-- Verification itself never depends on this column — `signer_public_key` is
-- already stored per-receipt, so old receipts stay verifiable forever after
-- the active key rotates. NULL when unsigned or when no key_id was supplied.
ALTER TABLE action_receipts ADD COLUMN signer_key_id TEXT;

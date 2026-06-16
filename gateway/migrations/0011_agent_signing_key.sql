-- #1403: agent-to-gateway request signing.
-- Adds an optional HMAC-SHA256 signing key per agent. When set, every
-- /v1/authorize call from that agent must include an
-- X-Aegis-Request-Signature: sha256=<hmac-hex> header that the gateway
-- verifies against the raw request body. Opt-in (NULL = unsigned, backwards
-- compatible). Key is stored in plaintext; protect the DB file at rest.
ALTER TABLE agents ADD COLUMN signing_key TEXT;

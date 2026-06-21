# Runbook: Rotating `AEGIS_JWT_SECRET` and `AEGIS_RECEIPT_SIGNING_KEY`

**Config:** `AEGIS_JWT_SECRET` · `AEGIS_RECEIPT_SIGNING_KEY` (#1211)

Unlike the [agent token rotation](agent-token-rotation.md) runbook (a per-agent, API-driven, often incident-triggered rotation), these two are process-wide environment secrets rotated on a routine schedule or after a suspected exposure of the deployment environment itself (e.g. a leaked `.env`, a compromised CI secret store).

## Symptoms / when to rotate

- Routine rotation schedule (e.g. quarterly) for either secret.
- A suspected exposure of the gateway's deployment environment (not a specific agent token — see the agent token runbook for that).
- `AEGIS_RECEIPT_SIGNING_KEY` rotation as part of generating a fresh Ed25519 keypair for receipt signing.

## `AEGIS_JWT_SECRET` — zero-downtime rotation

`AEGIS_JWT_SECRET` accepts a comma-separated list. `validate_jwt` tries each entry in order until one decodes the token, so multiple secrets can be valid simultaneously during a rotation window. Blank entries and the literal `default_secret` sentinel are always filtered out, so a stray trailing comma can't silently widen what's accepted.

1. **Add the new secret first, keep the old one:**
   ```bash
   AEGIS_JWT_SECRET="new_secret_value,old_secret_value"
   ```
   Tokens signed with either secret validate during this window. Restart/roll the gateway to pick up the new value (it's read fresh per `validate_jwt` call from the process environment, but the environment itself only changes on restart in most deployments).
2. **Start issuing new tokens signed with the new secret.** The gateway itself never issues JWTs (it only validates externally-issued ones — see `validate_jwt` in `gateway/src/routes/mod.rs`), so this step happens in whatever system mints your JWTs.
3. **Wait out the rotation window** — at least as long as the longest-lived outstanding token's `exp`, so nothing still in circulation depends on the old secret.
4. **Drop the old secret:**
   ```bash
   AEGIS_JWT_SECRET="new_secret_value"
   ```
   Restart/roll again. Tokens signed with the old secret now fail `validate_jwt` and are rejected.

### Verification

```bash
# A token signed with the dropped secret should now be rejected:
curl -s -H "Authorization: Bearer $OLD_SIGNED_TOKEN" "http://127.0.0.1:8080/v1/decisions"
# -> 401, reason: "Unauthorized"
```

## `AEGIS_RECEIPT_SIGNING_KEY` — key rotation

Each signed receipt embeds its own `signer_public_key` (and, if the value below uses the `key_id:` prefix, `signer_key_id`) **at signing time** — verification (`GET /v1/receipts/:id/verify`) always uses the key stored on that specific receipt, never a live lookup against the currently-configured key. This means **old receipts stay verifiable forever after the active key rotates** — there is no "rotation window" to manage for verification, unlike the JWT secret above.

1. **Generate a new Ed25519 keypair** (32-byte secret, hex-encoded — see `ReceiptSigner::from_secret_hex` in `gateway/src/sign.rs` for the expected format).
2. **Optionally tag it with a human-readable key ID** so future audits can tell which generation of key signed a given receipt without recognizing a raw public-key hex string:
   ```bash
   AEGIS_RECEIPT_SIGNING_KEY="rotation-2026-06:<new_32_byte_secret_hex>"
   ```
   A bare `AEGIS_RECEIPT_SIGNING_KEY="<hex_secret>"` (no `key_id:` prefix) remains valid — `signer_key_id` is simply `null` on receipts signed under it.
3. **Restart the gateway.** `sign::global_signer()` is initialized once per process via `OnceLock` from the environment, so picking up a new key requires a restart (or a rolling restart across replicas for zero downtime — there is no live-reload endpoint for this value, unlike `POST /v1/policies/reload`).
4. **Retire the old secret material** (delete it from wherever it was provisioned) once you're confident no in-flight signing is still using it. This is safe immediately — there's no "wait for old tokens to expire" concern, because old receipts don't need the old key to stay verifiable.

### Verification

```bash
# A receipt signed before rotation still verifies after the key changes:
curl -s "http://127.0.0.1:8080/v1/receipts/<old_receipt_id>/verify"
# -> {"verified": true, "signature_verified": true, "signer_key_id": "<old key id, if any>", ...}

# A receipt signed after rotation carries the new key id:
curl -s "http://127.0.0.1:8080/v1/receipts/<new_receipt_id>/verify"
# -> {"verified": true, "signature_verified": true, "signer_key_id": "rotation-2026-06", ...}
```

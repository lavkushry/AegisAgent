# Runbook: Verifying Receipt Chain Integrity

**Endpoints:** `GET /v1/receipts/:id/verify` · `POST /v1/receipts/verify-chain` · **CLI:** `aegis-verify-receipts` (or `python3 -m aegisagent.verify_receipts`)

## Symptoms

- A `receipt-chain-broken` SOC alert (P1 per [`AegisAgent_Threat_Model.md`](../AegisAgent_Threat_Model.md) T-C1).
- Routine compliance/audit prep (SOC 2, EU AI Act Art. 14) — proving the evidence trail hasn't been tampered with.
- Post-incident: confirming an attacker (or a bug) didn't alter or drop receipts to hide an action, after any of the other runbooks' containment steps.
- Post-restore: confirming a database restore (see [`backup-and-restore.md`](backup-and-restore.md)) didn't break chain continuity.

## Background

Every action receipt is hash-chained: each receipt's hash is computed over its own fields plus `prev_receipt_hash` (the previous receipt in that tenant's chain). Altering, reordering, or dropping a receipt breaks the chain from that point forward — this is the entire point of the design (T-C1/T-C2 in the threat model).

## Investigation

1. **Verify a single receipt** (recomputes its hash and checks it matches what's stored; also reports signature status if Ed25519 signing is configured):
   ```bash
   curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/receipts/<receipt_id>/verify"
   ```
   ```json
   {
     "receipt_id": "...", "verified": true,
     "receipt_hash": "...", "recomputed_hash": "...", "prev_receipt_hash": "...",
     "signed": true, "signature_verified": true, "signer_public_key": "..."
   }
   ```
   `verified: false` means the stored `receipt_hash` doesn't match what the receipt's own fields recompute to — the receipt itself was altered. `signature_verified` is `null` when no signer was configured for that receipt (signing is optional, see `sign.rs`); it never affects `verified`, since hash-chain integrity and signature verification are independent checks.

2. **Verify a whole chain** by fetching the relevant receipts and submitting them together — this endpoint validates the `prev_receipt_hash` links between them, not just each receipt in isolation:
   ```bash
   RECEIPTS=$(curl -s -H "Authorization: Bearer $AGENT_TOKEN" "http://127.0.0.1:8080/v1/receipts" | jq -c .)
   curl -s -X POST -H "Authorization: Bearer $AGENT_TOKEN" \
     "http://127.0.0.1:8080/v1/receipts/verify-chain" \
     -d "{\"receipts\": $RECEIPTS}"
   # {"verified": true, "error": null}
   ```
   An empty `receipts` array trivially returns `verified: true` — make sure you actually fetched receipts before trusting a `true` result.

3. **Same check, offline, via the CLI** (useful for verifying an exported evidence pack without hitting a live gateway):
   ```bash
   aegis-verify-receipts path/to/receipts.json
   # or: python3 -m aegisagent.verify_receipts path/to/receipts.json
   ```

4. **Narrow down where the break is.** If a chain-level check fails, bisect: verify the first half, then the second half, to find the first receipt where `prev_receipt_hash` no longer matches the prior receipt's `receipt_hash` — that's your tamper/drop point. Cross-reference that receipt's `decision_id` against `GET /v1/decisions/:id` and `GET /v1/audit/events` to see what action it covers and who/what touched it around that time.

## Remediation

- **A single receipt fails individual verification (`verified: false`):** this is direct evidence of tampering or storage corruption. Treat it as a security incident, not a data-quality bug — preserve the broken state (don't "fix" the hash) and investigate via the database's own audit trail (who had write access, any recent migrations/restores, disk-level corruption).
- **A chain-level check fails but individual receipts verify:** a receipt was likely **dropped or reordered** rather than edited — check for gaps in `created_at`/sequence around the break point.
- **Caused by a restore from an older backup:** confirm with the team whether decisions made *after* that backup's point-in-time are expected to be missing (this is not tampering, just an accepted consequence of restoring to an earlier state) — document this explicitly rather than treating it as an unexplained break.
- **Signature mismatch (`signature_verified: false`) with hash verification still `true`:** the receipt's content is intact, but its signature doesn't match — check whether the signing key was rotated and an old `signer_public_key` is being compared against a receipt signed after rotation; this is a configuration issue, not necessarily tampering.

## Verification

- Re-run the chain-level check across the full receipt range for the affected tenant; it should now return `verified: true`.
- File/update the incident record citing the specific `receipt_id` where the break was found and the root cause determined above.
- If this was a genuine tamper event (not a benign restore gap), treat it with the same urgency as the `data_exfiltration.md` runbook — rotate any credentials that may have allowed direct database write access, and review who/what has that access going forward.

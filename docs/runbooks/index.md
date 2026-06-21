# Operational Runbooks

**Issue:** [#1199](https://github.com/lavkushry/AegisAgent/issues/1199)

Step-by-step procedures for the most common SOC scenarios. Each follows the same shape: **Symptoms** (how you'd notice this), **Investigation** (how to confirm and scope it), **Remediation** (what to do about it), **Verification** (how to confirm it's actually resolved).

| Runbook | Use when |
|---|---|
| [Deny storm](deny-storm.md) | An agent accumulates repeated denied actions in a short window — likely misconfiguration or active probing. |
| [Data exfiltration pattern](data-exfiltration.md) | A read action is followed by an external write/send for the same agent — the confused-deputy exfil pattern. |
| [Agent token rotation](agent-token-rotation.md) | A token may have leaked, or you need to rotate one proactively. |
| [Backup and restore](backup-and-restore.md) | Before a risky migration, or recovering from corruption/accidental deletion. |
| [Receipt chain verification](receipt-chain-verification.md) | Confirming the evidence trail hasn't been tampered with — routine compliance prep or post-incident verification. |
| [Secret rotation](secret-rotation.md) | Routine or post-exposure rotation of `AEGIS_JWT_SECRET` or `AEGIS_RECEIPT_SIGNING_KEY` — process-wide secrets, not a specific agent's token. |

These assume familiarity with the SOC architecture in [`AegisAgent_Agent_SOC_Design.md`](../AegisAgent_Agent_SOC_Design.md) (the Four Design Laws, autonomy levels `L0`–`L4`) and the [evidence graph](../evidence-graph.md) query API used throughout for investigation.

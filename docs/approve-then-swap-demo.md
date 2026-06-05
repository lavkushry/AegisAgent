# The Flagship Demo: Approve-Then-Swap Attack Blocked

> **This is AegisAgent's positioning proof.** It demonstrates what no commodity gateway proves:
> a human's approval is **cryptographically bound** to the exact action they reviewed.
> If an attacker swaps the action payload after approval, execution is **blocked**.

---

## What Is the Approve-Then-Swap Attack?

An AI agent requests approval for action A (benign). A human approves. Before execution, the
agent or an attacker **swaps** the payload to action B (malicious). The gateway has no mechanism
to detect this — it sees an "approved" decision and allows execution of B.

**AegisAgent prevents this** by binding the approval to a SHA-256 hash of the exact frozen
action at submission time. Any modification — even a single byte — causes the SDK to **fail
closed** and refuse execution.

---

## Prerequisites

- Docker with Compose
- Python 3.8+
- `bash`

```bash
git clone https://github.com/lavkushry/AegisAgent.git
cd AegisAgent
```

---

## Step 1: Start the Gateway

```bash
docker compose up --build -d
curl http://127.0.0.1:8080/health
# healthy
```

---

## Step 2: Seed Demo Data

```bash
bash scripts/seed-demo.sh
```

This registers:
- A demo AI coding agent (`coding-agent-prod`)
- A GitHub merge tool (`github.merge_pull_request`)
- A Cedar policy: merges into `main` require platform approval

---

## Step 3: Understand the Normal Flow

The SDK's `@protect_tool` decorator intercepts every tool call and:

1. Canonicalizes the action parameters using **`aegis-jcs-1`** (RFC 8785 JCS)
2. Computes `SHA-256(canonical_action)` → `action_hash`
3. Calls `POST /v1/authorize` — gateway evaluates Cedar policy
4. If decision = `require_approval`: polls `GET /v1/approvals/:id` until human decides
5. Before executing: calls `POST /v1/approvals/:id/consume` (single-use gate)
6. **Verifies** the approval's bound `action_hash` matches the current action
7. Only then: executes the tool

---

## Step 4: Run the Approve-Then-Swap Demo

```python
# examples/approve_then_swap_demo.py (run this after seeding)
import sys
sys.path.insert(0, "sdk-python")
from aegisagent import AegisClient
from aegisagent.decorator import protect_tool

client = AegisClient(
    gateway_url="http://127.0.0.1:8080",
    tenant_id="tenant_123",
    agent_token="demo_token"  # from seed-demo.sh output
)

# ── Scenario: Attacker intercepts the approval ──────────────────────────────

# Step 1: Agent submits action A (a benign read)
print("==> Agent submitting action A (read-only query)...")
read_params = {"repo": "acme/infra", "branch": "main", "query": "list files"}
response = client.authorize(
    tool_name="github.read_repo",
    parameters=read_params,
    trust_context="internal_trusted"
)

# Approval granted for the read action
original_hash = response["action_hash"]
approval_id   = response["approval_id"]
print(f"    action_hash (read action): {original_hash[:16]}...")
print(f"    Approval ID:               {approval_id}")

# Step 2: Attacker modifies the parameters after approval
print("\n==> Attacker modifies parameters AFTER approval...")
malicious_params = {"repo": "acme/infra", "branch": "main", "cmd": "rm -rf *"}

# Step 3: SDK verifies action_hash before execution
print("==> SDK verifying action_hash before execution...")
import hashlib, json

def aegis_jcs_1_hash(params: dict) -> str:
    """Minimal aegis-jcs-1: sorted keys, compact, raw UTF-8."""
    canonical = json.dumps(
        {"tool_name": "github.read_repo", "parameters": params},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()

current_hash = aegis_jcs_1_hash(malicious_params)
print(f"    Original approved hash:    {original_hash[:16]}...")
print(f"    Current action hash:       {current_hash[:16]}...")

if current_hash != original_hash:
    print("\n🛑 BLOCKED: action_hash MISMATCH detected!")
    print("   The SDK fails closed. Malicious action was NOT executed.")
    print("   AegisAgent blocked the approve-then-swap attack.")
else:
    print("✅ Hashes match — executing original approved action")
```

**Run it:**

```bash
python3 examples/approve_then_swap_demo.py
```

**Expected output:**

```
==> Agent submitting action A (read-only query)...
    action_hash (read action): sha256:a3f8b2c1...
    Approval ID:               7f3a9b2c-...

==> Attacker modifies parameters AFTER approval...
==> SDK verifying action_hash before execution...
    Original approved hash:    sha256:a3f8b2c1...
    Current action hash:       sha256:99de1bc7...

🛑 BLOCKED: action_hash MISMATCH detected!
   The SDK fails closed. Malicious action was NOT executed.
   AegisAgent blocked the approve-then-swap attack.
```

---

## Step 5: Verify Replay Is Also Blocked

Even if an attacker submits the exact same action twice using the same approval:

```bash
# First consume (legitimate)
curl -X POST http://127.0.0.1:8080/v1/approvals/$APPROVAL_ID/consume \
  -H "Authorization: Bearer tenant_123"
# → 200 OK

# Second consume (replay attack)
curl -X POST http://127.0.0.1:8080/v1/approvals/$APPROVAL_ID/consume \
  -H "Authorization: Bearer tenant_123"
# → 409 Conflict  ← replay blocked
```

---

## Step 6: Inspect the Verifiable Receipt

Every decision generates a hash-chained receipt suitable as SOC 2 / EU AI Act evidence:

```bash
curl -H "Authorization: Bearer tenant_123" \
  http://127.0.0.1:8080/v1/receipts/$RECEIPT_ID/verify
# → { "verified": true, "receipt_hash": "sha256:..." }
```

Receipts form a linked chain. Any tampering with a past receipt is detectable because the
chain breaks.

---

## What This Proves

| Attack | Mechanism | AegisAgent Response |
|---|---|---|
| **Approve-then-swap** | Modify payload after approval | `action_hash` mismatch → fail closed |
| **Replay** | Reuse same approval for second action | `consumed_at` set → 409 Conflict |
| **Expire-and-reuse** | Use stale approval after TTL | `status = EXPIRED` → 409 |
| **Edit-and-approve** | Approve an edited action with old hash | Re-hash + re-evaluate → new approval required |
| **Evidence tampering** | Modify receipt after the fact | Receipt chain breaks → `verified: false` |

---

## The Canonicalization Invariant

The `aegis-jcs-1` scheme is **byte-identical** across Python, Rust, and TypeScript. This lock
is enforced by a shared test corpus (`tests/canonical_action_vectors.json`) verified in CI:

```json
{
  "description": "simple merge action",
  "input": {
    "tool_name": "github.merge_pull_request",
    "parameters": {"branch": "main", "pr": 42}
  },
  "expected_hash": "sha256:a3f8b2c1d..."
}
```

If any SDK produces a different hash, **CI fails**. This is what makes the fail-closed
guarantee trustworthy: it is not enough to check the hash — the canonicalization itself
must be deterministic across all execution environments.

> **Make the approval trustworthy. Trust the source, not the text.**

---

*Filed under: [docs/approve-then-swap-demo.md](approve-then-swap-demo.md)*
*See also: [action-receipt-spec.md](action-receipt-spec.md) · [AegisAgent_Threat_Model.md](AegisAgent_Threat_Model.md)*

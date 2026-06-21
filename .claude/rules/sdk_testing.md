---
globs:
  - "sdk-python/**/*"
  - "sdk-typescript/**/*"
  - "sdk-go/**/*"
---

# AI Skill: SDK Interception & Polling Validation (`skills/sdk_testing.md`)

This skill describes how to verify client-side tool call interceptions, mock network layers, and test approval loops in the Python SDK.

---

## 1. Interception Design & Test Targets

The SDK decorator `@protect_tool` wraps agent function execution. 

### Key Test Vectors:
- **Authorization Success (Allow):** The tool executes immediately without latency.
- **Authorization Failure (Deny):** A `AegisAuthorizationDenied` exception is raised, and the tool does NOT execute.
- **Human Approval (RequireApproval):** The decorator catches the approval ID, enters a blocking-polling loop, and only executes the tool once the approval state transitions to `approved`.

---

## 2. Unit Testing Mock Strategy (Python)

Unit tests must not rely on a live running gateway. Use the `unittest.mock` framework to intercept requests.

### Mock Code Example:

```python
import unittest
from unittest.mock import patch, MagicMock
from aegisagent import protect_tool, AegisAuthorizationDenied

# Mock Target Tool
@protect_tool(tool_key="github", action_key="commit")
def commit_code(branch, message):
    return "Committed successfully"

class TestSDKInterception(unittest.TestCase):
    
    @patch('aegisagent.client.requests.post')
    def test_instant_allow(self, mock_post):
        # Mock allow decision from gateway
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "decision": "allow",
            "reason": "Permitted by policy"
        }
        mock_post.return_value = mock_response
        
        result = commit_code(branch="feature", message="adds feature")
        self.assertEqual(result, "Committed successfully")

    @patch('aegisagent.client.requests.post')
    def test_instant_deny(self, mock_post):
        # Mock deny decision from gateway
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "decision": "deny",
            "reason": "Forbidden: High risk action"
        }
        mock_post.return_value = mock_response
        
        with self.assertRaises(AegisAuthorizationDenied):
            commit_code(branch="main", message="direct push")

    @patch('aegisagent.client.requests.get')
    @patch('aegisagent.client.requests.post')
    def test_polling_approval(self, mock_post, mock_get):
        # 1. Authorize returns require_approval
        auth_response = MagicMock()
        auth_response.status_code = 200
        auth_response.json.return_value = {
            "decision": "require_approval",
            "approval_id": "893c5d64-1234-4321-9988-aabbccddeeff"
        }
        mock_post.return_value = auth_response

        # 2. Mock polling states: first check is pending, second check is approved
        pending_response = MagicMock()
        pending_response.status_code = 200
        pending_response.json.return_value = {"status": "pending"}

        approved_response = MagicMock()
        approved_response.status_code = 200
        approved_response.json.return_value = {"status": "approved"}

        mock_get.side_effect = [pending_response, approved_response]

        # Invoke decorator (uses standard 1-second poll interval)
        with patch('time.sleep', return_value=None): # Bypass sleep delay for test speed
            result = commit_code(branch="main", message="valid commit")
        
        self.assertEqual(result, "Committed successfully")
```

---

## 3. Integration Testing with Mock Server

For end-to-end checks, we use a loopback integration server.

### Runbook Steps:
1. Ensure the gateway server is compiling and running:
   ```bash
   cargo run --manifest-path gateway/Cargo.toml
   ```
2. In a separate shell, run the integration harness script:
   ```bash
   python examples/mock_server.py
   ```
3. **Verify the execution trace:** The script logs the full trace. Ensure it asserts:
   - A safe command runs in < 2ms.
   - A sensitive command holds execution, registers the approval task, receives a simulated approval call, and successfully completes.

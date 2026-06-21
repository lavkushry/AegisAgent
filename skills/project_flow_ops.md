---
globs:
  - "**/*.rs"
  - "**/*.py"
  - "**/*.ts"
  - "**/*.go"
  - "**/*.md"
---

# AI Skill: Project Flow & Release Operations (`skills/project_flow_ops.md`)

This skill defines the development lifecycles, git branch policies, testing workflows, compilation checks, and deployment validation steps for AegisAgent.

---

## 1. Local Development Flow

Before making changes, the agent must run the local development stack to establish a baseline.

### Steps:
1. **Initialize Workspace Rules:** Load the active agent profile using the harness:
   ```bash
   bash scripts/setup_agent_harness.sh --profile developer
   ```
2. **Launch Database & Server:** Initialize compile checks:
   ```bash
   cargo check --manifest-path gateway/Cargo.toml
   ```

---

## 2. Testing & Verification Flow

Every modification must pass our automated verification suite.

### Steps:
1. **Run Rust Gateway Tests:**
   ```bash
   cargo test --manifest-path gateway/Cargo.toml
   ```
2. **Run Python SDK Tests:**
   ```bash
   python -m unittest discover -s sdk-python
   ```
3. **Run End-to-End Mock Integration:**
   Start the local gateway in one terminal, and in another run the mock client/approval loop integration script:
   ```bash
   python examples/mock_server.py
   ```

---

## 3. Pre-Release Auditing (Ops Guidelines)

Before files are staged or merged into the main branch, they must pass security and format audits.

### Steps:
1. **Regenerate SQLx Metadata (Offline Mode):**
   If database schemas are altered, compile and update `sqlx-data.json`:
   ```bash
   export DATABASE_URL="sqlite://db/aegisagent.db"
   cargo sqlx prepare -- --all-targets
   ```
2. **Verify Formatting:**
   ```bash
   cargo fmt --manifest-path gateway/Cargo.toml -- --check
   black --check sdk-python/
   ```
3. **Build the Production Release Artifact:**
   ```bash
   cargo build --release --manifest-path gateway/Cargo.toml
   ```

---

## 4. Deployment Operations

When deploying releases using Helm or Docker:
- Verify that the container configurations bind endpoints to loopbacks or private subnets unless exposing public entry points.
- Ensure all Helm charts lint successfully:
  ```bash
  helm lint helm/aegisagent
  ```

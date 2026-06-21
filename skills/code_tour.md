---
globs:
  - "**/*.md"
  - "*"
---

# AI Skill: Codebase Onboarding Tour (`skills/code_tour.md`)

This skill provides AI developer agents with a step-by-step tour of the AegisAgent codebase structure, files, and design boundaries.

---

## 1. Directory Tree Architecture

The AegisAgent codebase is organized as follows:

```text
AegisAgent/
├── .claude/              # Runtime rules & project metadata (harness-generated)
├── docs/                 # Product PRDs and operational design specs
├── scripts/              # Workspace automation and plan scanning scripts
├── skills/               # Reusable AI agent skill runbooks (Markdown guides)
├── gateway/              # Rust Axum Gateway Proxy service
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs       # Server entry point, DB pool connection, routes
│   │   ├── config.rs     # Configuration manager (local bindings check)
│   │   ├── db.rs         # Parameterized SQLite queries (Multi-Tenant bound)
│   │   ├── policy.rs     # Cedar authorization evaluator & parser
│   │   ├── handlers.rs   # API route handlers (register, authorize, approvals)
│   │   └── models.rs     # Serialization data models
│   └── policies.cedar    # AWS Cedar Policy rules bundle
├── sdk-python/           # Python SDK package
│   ├── aegisagent/
│   │   ├── __init__.py
│   │   ├── client.py     # Network connection handler
│   │   └── decorator.py  # @protect_tool decorator and blocking-polling loop
│   └── setup.py
├── sdk-typescript/       # TypeScript SDK package (alpha)
├── policy-templates/     # Base reusable Cedar policy configs
├── mcp-gateway-lite/     # MCP proxy routing middleware
├── examples/             # Client-side validation examples
│   ├── demo_agent.py     # Simple protected tool runner
│   └── mock_server.py    # Loopback approval integration harness
└── helm/                 # Deployment charts
```

---

## 2. Onboarding Workflow for Developer Agents

When exploring the codebase, study modules in this order:

1. **Gateway Initialization (`gateway/src/main.rs`):**
   Understand how database connection pools, local bindings (`127.0.0.1:8080`), and routing middlewares are established.
2. **Database Layer (`gateway/src/db.rs`):**
   Review query structures. Verify that all methods accept `tenant_id` and bind variables parameterized exclusively.
3. **Authorization Engine (`gateway/src/policy.rs` & `gateway/policies.cedar`):**
   Inspect how Cedar queries are composed. Examine how annotations (e.g. `@decision("require_approval")`) are parsed to trigger manual reviews.
4. **Client Interceptor (`sdk-python/aegisagent/decorator.py`):**
   Observe how the `@protect_tool` wrapper intercepts tool execution, sends authorization requests to the gateway, and polls the pending approvals queue.
5. **Integration Loop (`examples/mock_server.py`):**
   Observe the mock testing harness to understand how the proxy handles instant approvals or blocks.

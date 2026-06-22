# Security Policy

AegisAgent is an integrity and enforcement layer for AI agent actions and should
be treated as security-critical infrastructure. We take vulnerabilities seriously.

## Supported Versions

| Version | Supported |
|---|---|
| `0.1.0-beta.x` | ✅ Current development focus |
| `main` (unreleased) | ✅ Security fixes applied immediately |
| Older commits | ❌ No backports — upgrade to latest beta |

Once stable releases begin (`v0.1.0`+), the latest minor release will receive
security patches. Critical vulnerabilities may receive backports to the
previous minor.

## Reporting a Vulnerability

**Please report vulnerabilities privately — do not open a public issue for an
exploitable flaw.**

Use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** (Security Advisories).
3. Provide the details below.

This routes the report privately to the maintainers and supports coordinated
disclosure and CVE issuance.

Please include:

- Affected component and version/commit.
- Reproduction steps or proof of concept.
- Impact assessment and any known mitigations.

We aim to acknowledge reports within **3 business days** and to provide
remediation status updates as fixes progress. We support coordinated disclosure
and will credit reporters who wish to be named.

## Scope

In scope: the Rust gateway, the Python SDK, the Go SDK, the TypeScript SDK,
the default Cedar policy pack, the canonicalization scheme, and the
action-receipt format/verifier.

Particularly sensitive areas (a flaw here can break the product's core
guarantee):

- **Canonicalization (`aegis-jcs-1`)** — any cross-language divergence can break
  the fail-closed approval guarantee.
- **Approval integrity** — action-hash binding, expiry, single-use consumption.
- **Trust-provenance gating** — anything that lets a classifier *loosen* a label.
- **Multi-tenant isolation** — cross-tenant data access.
- **Receipt hash chain** — tampering that is not detected by `/verify`.

## Secure Development Expectations

- Unknown agents, tools, MCP servers, and MCP tools fail closed.
- Critical actions are denied by default; high-risk actions require approval.
- Approval decisions bind to the original `action_hash`; edits re-hash and
  re-evaluate; approvals expire and are single-use.
- The canonicalization scheme stays byte-identical across SDK and gateway,
  locked by shared corpora and a CI byte-equality gate.
- Every database operation is tenant-scoped with parameterized SQL only.
- Secrets are never logged in audit events, traces, receipts, or demo output;
  receipts store hashes, not raw payloads.
- All database access uses the `StorageBackend` trait — never raw `SqlitePool`.
- No `.unwrap()`/`.expect()` in production code paths.

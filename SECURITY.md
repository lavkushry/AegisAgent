# Security Policy

AegisAgent is an agent action firewall and should be treated as security-critical infrastructure.

## Supported Versions

The project is pre-1.0. Security fixes target the `main` branch until versioned releases begin.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately by email:

- Security contact: `security@example.com`

Do not open public GitHub issues for exploitable vulnerabilities. Include:

- Affected component and version/commit.
- Reproduction steps or proof of concept.
- Impact assessment and any known mitigations.

We aim to acknowledge reports within 3 business days and provide remediation status updates as fixes progress.

## Security.txt

When hosted, publish `/.well-known/security.txt` pointing to this policy and the disclosure contact above.

## Secure Development Expectations

- Unknown agents, tools, MCP servers, and MCP tools fail closed.
- Approval decisions must bind to the original action hash.
- Every database operation must be tenant-scoped with parameterized SQL.
- Secrets must not be logged in audit events, traces, or demo output.

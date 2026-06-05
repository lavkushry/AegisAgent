# `.claude/` — how AegisAgent is managed with Claude Code

This project uses Claude Code's **native** setup (subagents + slash commands + memory), alongside the
existing context harness (`rules/`, `PRPs/`). Modeled on
[tinyhumansai/openhuman](https://github.com/tinyhumansai/openhuman/tree/main/.claude).

## Subagents — `.claude/agents/`

Spawn with the Agent tool, or let them auto-match by `description`:

| Agent | Use for | Model |
|---|---|---|
| `architect` | design + docs + schema/API review | opus |
| `gateway-dev` | Rust Axum gateway (routes/db/policy), TDD | sonnet |
| `sdk-dev` | Python/Go/TS SDKs + `aegis-jcs-1` canon byte-parity | sonnet |
| `security-auditor` | Cedar, tenant isolation, fail-closed, threat model | opus |
| `pr-reviewer` | review the diff against the invariants | sonnet |
| `memory-keeper` | update project memory | sonnet |
| `docs-agent` | `docs/` + the MkDocs site | sonnet |

## Commands — `.claude/commands/` (type `/<name>`)

- **`/verify`** — full cross-language verification (gateway + Python + Go + TS canon parity)
- **`/security-audit`** — the security runbook (tenant isolation, SQL param, fail-closed, secrets)
- **`/new-policy`** — add a Cedar policy TDD-style (RED → GREEN)
- **`/docs`** — build / preview / publish the docs site
- **`/ship`** — commit → push → PR → babysit CI

## `settings.json`

A permissions allowlist for safe dev/test/read commands (cargo/go/node/python tests, `mkdocs`, read-only
git/gh) → fewer approval prompts. Also wires the hooks below.

## Hooks — `.claude/hooks/` (deterministic guardrails)

This is the "Anthropic-grade" piece: invariants enforced by code, not by hoping the model remembers.

- **`guard.sh`** (`PreToolUse` on Edit/Write/MultiEdit) — before an edit lands, *asks* for confirmation
  when the target is a load-bearing file: the byte-parity-locked canon vectors
  (`tests/{canonical_action_vectors,receipt_chain_vectors}.json`), a `canon.{py,go,ts}` canonicalizer, or a
  harness-generated `.clauderules`/`.cursorrules`. It surfaces *why* (the scheme-bump invariant). It asks,
  never hard-denies — you stay in control. This makes AegisAgent's own thesis (deterministic gating) the way
  the repo is edited.
- **`fmt.sh`** (`PostToolUse` on Edit/Write/MultiEdit) — auto-formats the edited file by type
  (`cargo fmt` for gateway Rust, `gofmt` for Go, `black` for Python). Skips silently if the toolchain is
  absent; never blocks. Keeps `cargo fmt -- --check` / `black --check` green by construction.

Both parse the hook's stdin JSON with `python3` (no `jq` dependency).

## Memory

`/home/ems/.claude/projects/-home-ems-AegisAgent/memory/` — **one fact per file** + a `MEMORY.md` index.
Use the `memory-keeper` agent to update it at the end of substantial work.

## `rules/` and `PRPs/` (existing harness — left intact)

`rules/` holds path-gated context + project personas/skills (harness-generated via
`scripts/setup_agent_harness.sh` — don't hand-edit the generated ones). `PRPs/` holds the plan/task/report
registry. These coexist with the native setup above.

## Authoritative context

`CLAUDE.md` (commands, invariants, layout) · `AGENTS.md` (persona scopes) · `docs/` (product +
architecture, published at https://lavkushry.github.io/AegisAgent/).

#!/usr/bin/env bash
#
# close_resolved_issues.sh — owner-run helper to close auto-generated issue stubs.
#
# WHY: the `create_1000_github_issues` bulk script over-generated ~863 issues.
# Triage (2026-06-06) found most are EITHER (a) already satisfied by shipped code,
# OR (b) empty stubs whose bodies point at `implementation_plan.md` "Track N" task
# breakdowns that do not exist in the repo (no actionable spec). This script lets
# YOU — the repo owner — close them in controlled, auditable batches. An AI agent
# is deliberately NOT doing this in bulk (it's a large, public, outward-facing write).
#
# SAFE BY DEFAULT: dry-run. Preview first, then opt in.
#   bash scripts/close_resolved_issues.sh                 # dry-run (prints, closes nothing)
#   DRY_RUN=0 bash scripts/close_resolved_issues.sh       # actually close
#
# Requires: gh (authenticated as a user with write access to the repo).

set -uo pipefail
REPO="${REPO:-lavkushry/AegisAgent}"
DRY_RUN="${DRY_RUN:-1}"

# close_label <label> <comment>
# Closes every OPEN issue carrying <label>, each with an audit comment.
close_label() {
  local label="$1" comment="$2"
  local nums
  nums=$(gh issue list --repo "$REPO" --state open --label "$label" --limit 200 \
           --json number --jq '.[].number' 2>/dev/null)
  if [ -z "$nums" ]; then
    echo "  (no open issues with label '$label')"
    return
  fi
  for n in $nums; do
    if [ "$DRY_RUN" = "1" ]; then
      echo "  [dry-run] would close #$n   ($label)"
    else
      gh issue close "$n" --repo "$REPO" --comment "$comment" >/dev/null 2>&1 \
        && echo "  closed #$n" || echo "  !! failed #$n (already closed / no perms?)"
    fi
  done
}

echo "Repo: $REPO   DRY_RUN=$DRY_RUN"
echo

# ── (A) VERIFIED ALREADY-IMPLEMENTED ─────────────────────────────────────────
# The whole TypeScript SDK parity goal is shipped (sdk-typescript/src/{client,
# protect,canon}.ts; 20 tests; `tsc --noEmit` clean). Every track/ts-sdk issue is
# an identical stub whose goal this satisfies. Verified file-by-file during triage.
echo "(A) track/ts-sdk — TypeScript SDK parity already implemented:"
close_label "track/ts-sdk" \
  "Resolved during triage: the TypeScript SDK parity goal for this track is already implemented in sdk-typescript/src/{client,protect,canon}.ts (fail-closed client + @protect wrapper + aegis-jcs-1 canon) with 20 passing tests and a clean strict tsc build. This was an auto-generated stub with no per-task spec; closing as done."

# ── (B) EMPTY OVER-GENERATION (opt-in: uncomment to clean the tracker) ────────
# These tracks' issues reference `implementation_plan.md` task breakdowns that do
# NOT exist in the repo — there is no actionable spec to implement. Closing them
# is a tracker-hygiene decision; review a sample first, then uncomment to run.
#
# close_label "track/go-sdk" \
#   "Closing auto-generated stub: body references a non-existent implementation_plan.md task breakdown; the Go SDK goal (sdk-go/aegis + canon, fail-closed client + receipts, tests) is already shipped. Reopen with a concrete spec if a real task remains."
#
# Add more tracks here only after triaging them (don't blanket-close untriaged tracks).

echo
echo "Done. (DRY_RUN=$DRY_RUN — set DRY_RUN=0 to apply.)"

#!/usr/bin/env bash
# PreToolUse guard (Edit|Write|MultiEdit).
# Turns CLAUDE.md's "do not weaken" prose into a deterministic gate: asks for
# confirmation before an edit can silently break a load-bearing invariant.
# Emits a PreToolUse "ask" decision (not a hard deny) so you stay in control.
set -uo pipefail

fp="$(python3 -c 'import sys,json; print(json.load(sys.stdin).get("tool_input",{}).get("file_path",""))' 2>/dev/null || true)"
[ -z "$fp" ] && exit 0

reason=""
case "$fp" in
  *tests/canonical_action_vectors.json|*tests/receipt_chain_vectors.json)
    reason="This file LOCKS aegis-jcs-1 byte-parity across every SDK (Go/TS/Python) + the gateway. Editing a vector in place silently breaks the fail-closed guarantee. Per CLAUDE.md you MUST bump the canon scheme and add a CI byte-equality check — not mutate vectors. Confirm only if you are deliberately re-locking the corpus." ;;
  *canon.py|*canon.go|*canon.ts)
    reason="Canonicalizer source. aegis-jcs-1 MUST stay byte-identical across SDK + gateway; a divergence silently defeats fail-closed. Run /verify (cross-language corpus) after any change to this file." ;;
  *.clauderules|*.cursorrules)
    reason="Harness-generated file (scripts/setup_agent_harness.sh). Hand-edits get overwritten — regenerate instead of editing." ;;
  *)
    exit 0 ;;
esac

python3 - "$reason" <<'PY'
import json, sys
print(json.dumps({
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": sys.argv[1],
    }
}))
PY
exit 0

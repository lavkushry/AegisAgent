#!/usr/bin/env bash
# PostToolUse formatter (Edit|Write|MultiEdit).
# Auto-formats the file Claude just edited, by type. Skips silently when the
# toolchain is absent (CLAUDE.md: "no toolchain in some envs"). Never blocks.
set -uo pipefail
cd "${CLAUDE_PROJECT_DIR:-$(pwd)}" || exit 0

fp="$(python3 -c 'import sys,json; print(json.load(sys.stdin).get("tool_input",{}).get("file_path",""))' 2>/dev/null || true)"
[ -z "$fp" ] && exit 0

case "$fp" in
  *gateway/*.rs)
    command -v cargo  >/dev/null 2>&1 && cargo fmt --manifest-path gateway/Cargo.toml >/dev/null 2>&1 || true ;;
  *sdk-go/*.go)
    command -v gofmt  >/dev/null 2>&1 && gofmt -w "$fp" >/dev/null 2>&1 || true ;;
  *sdk-python/*.py|*examples/*.py)
    command -v black  >/dev/null 2>&1 && black -q "$fp" >/dev/null 2>&1 || true ;;
esac
exit 0

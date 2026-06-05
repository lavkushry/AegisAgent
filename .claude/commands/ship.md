---
description: Commit the current changes, push to origin, optionally open/update a PR, then watch CI until green.
allowed-tools: Bash, Read, Edit, Write
---

Ship flow for `lavkushry/AegisAgent`. Be concise — one line per phase transition.

## Phase 1 — Commit
Run `git status`, `git diff` (staged+unstaged), and recent `git log` in parallel. Stage relevant files
(no secrets / large binaries / `.env`). Commit with a conventional prefix
(`feat:`/`fix:`/`refactor:`/`chore:`/`docs:`/`test:`) via HEREDOC, ending with:
`Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Never `--no-verify` your own changes.

## Phase 2 — Push
Confirm the branch (`git rev-parse --abbrev-ref HEAD`). Push to `origin` (`-u` if tracking is missing).
Never force-push `main`. If on `main`, that matches this repo's flow; if a feature branch, fine too.

## Phase 3 — PR (only if requested or on a feature branch)
`gh pr create --base main --title "..." --body "$(cat <<'EOF' ... EOF)"`. Inspect `git log main..HEAD`
and `git diff main...HEAD` to write the summary. Print the PR URL.

## Phase 4 — Babysit
Poll `gh run list --limit 5` until CI is green. Fix failures and re-push (a NEW commit; don't amend
pushed commits). If looping, pace with `ScheduleWakeup` ~270s. Exit when CI is clean.

> Note: a push to `main` touching `docs/**` also auto-deploys the docs site (Docs workflow → GitHub Pages).

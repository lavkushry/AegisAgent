"""CLI commands for AegisAgent SDK operational tasks.

Entry points (registered in pyproject.toml):

    aegis                   — unified dispatcher, kubectl-style (#1202):
                               aegis status | freeze-agent | unfreeze-agent |
                               verify-receipts | export-audit | soc-summary
    aegis-status            — show gateway health + version (TASK-0182)
    aegis-freeze-agent      — freeze an agent by ID (TASK-0181)
    aegis-export-audit      — export audit events as JSON/JSONL (TASK-0180)
    aegis-verify-receipts   — verify a receipt chain (TASK-0179)

All commands read ``AEGIS_API_KEY`` and ``AEGIS_ENDPOINT`` from the
environment (``AEGIS_ENDPOINT`` defaults to ``http://127.0.0.1:8080``).
"""

import argparse
import json
import os
import sys
from typing import List, Optional

import requests

# ANSI SGR codes for `_colorize`. Kept to a minimal, dependency-free set
# rather than pulling in a third-party coloring library for this.
GREEN = "32"
RED = "31"
CYAN = "36"


def _color_enabled() -> bool:
    """Honor the NO_COLOR convention (https://no-color.org/) and suppress
    color when stdout isn't a terminal (piped output, captured test output,
    `--format json` consumers), so scripted/redirected use never sees stray
    escape codes."""
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _colorize(text: str, code: str) -> str:
    if not _color_enabled():
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def _api_key() -> str:
    key = os.environ.get("AEGIS_API_KEY", "")
    if not key:
        print("ERROR: AEGIS_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(2)
    return key


def _endpoint() -> str:
    return os.environ.get("AEGIS_ENDPOINT", "http://127.0.0.1:8080").rstrip("/")


def _headers() -> dict:
    key = _api_key()
    tenant_id = key if key.startswith("tenant_") else "tenant_default"
    return {
        "Authorization": f"Bearer {key}",
        "X-Aegis-Tenant-ID": tenant_id,
        "Content-Type": "application/json",
    }


# ──────────────────────────────────────────────────────────────────────
# aegis-status  (TASK-0182)
# ──────────────────────────────────────────────────────────────────────
def status_main(argv: Optional[List[str]] = None) -> int:
    """Show gateway health and stats."""
    parser = argparse.ArgumentParser(
        prog="aegis-status",
        description="Show AegisAgent gateway health and stats.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output raw JSON (alias for --format json)",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default=None,
        help="Output format (default: table)",
    )
    args = parser.parse_args(argv)
    as_json = args.as_json or args.format == "json"

    endpoint = _endpoint()
    headers = _headers()

    # Health
    try:
        health_resp = requests.get(f"{endpoint}/health", timeout=5)
        health = (
            health_resp.json()
            if health_resp.status_code == 200
            else {"status": "unreachable"}
        )
    except Exception as exc:
        print(f"ERROR: cannot reach gateway at {endpoint}: {exc}", file=sys.stderr)
        return 1

    # Stats
    try:
        stats_resp = requests.get(f"{endpoint}/v1/stats", headers=headers, timeout=5)
        stats = stats_resp.json() if stats_resp.status_code == 200 else {}
    except Exception:
        stats = {}

    result = {"health": health, "stats": stats, "endpoint": endpoint}

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        status = health.get("status", "unknown")
        version = health.get("version", "unknown")
        status_color = GREEN if status == "ok" else RED
        print(f"Gateway:  {endpoint}")
        print(f"Status:   {_colorize(status, status_color)}")
        print(f"Version:  {version}")
        if stats:
            print("─" * 40)
            for k, v in stats.items():
                print(f"  {k}: {v}")

    return 0


# ──────────────────────────────────────────────────────────────────────
# aegis-freeze-agent  (TASK-0181)
# ──────────────────────────────────────────────────────────────────────
def freeze_agent_main(argv: Optional[List[str]] = None) -> int:
    """Freeze an agent by ID."""
    parser = argparse.ArgumentParser(
        prog="aegis-freeze-agent",
        description="Freeze an agent on the AegisAgent gateway.",
    )
    parser.add_argument("agent_id", help="Agent ID to freeze")
    parser.add_argument(
        "--unfreeze",
        action="store_true",
        help="Unfreeze (restore) the agent instead of freezing",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table)",
    )
    args = parser.parse_args(argv)

    endpoint = _endpoint()
    headers = _headers()
    verb = "unfreeze" if args.unfreeze else "freeze"

    try:
        resp = requests.post(
            f"{endpoint}/v1/agents/{args.agent_id}/{verb}",
            headers=headers,
            timeout=5,
        )
        if resp.status_code in (200, 201):
            if args.format == "json":
                print(
                    json.dumps(
                        {"agent_id": args.agent_id, "action": verb, "status": "ok"}
                    )
                )
            else:
                print(
                    _colorize(
                        f"OK: agent '{args.agent_id}' {verb}d successfully.", GREEN
                    )
                )
            return 0
        else:
            if args.format == "json":
                print(
                    json.dumps(
                        {
                            "agent_id": args.agent_id,
                            "action": verb,
                            "status": "failed",
                            "code": resp.status_code,
                            "body": resp.text,
                        }
                    )
                )
            else:
                print(
                    _colorize(f"FAILED: {resp.status_code} — {resp.text}", RED),
                    file=sys.stderr,
                )
            return 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


# ──────────────────────────────────────────────────────────────────────
# aegis-export-audit  (TASK-0180)
# ──────────────────────────────────────────────────────────────────────
def export_audit_main(argv: Optional[List[str]] = None) -> int:
    """Export audit events as JSON or JSONL."""
    parser = argparse.ArgumentParser(
        prog="aegis-export-audit",
        description="Export audit events from the AegisAgent gateway.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--jsonl",
        action="store_true",
        help="Output in JSON-lines format instead of JSON array",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Max number of events to fetch (default: 100)",
    )
    args = parser.parse_args(argv)

    endpoint = _endpoint()
    headers = _headers()

    try:
        resp = requests.get(
            f"{endpoint}/v1/audit/events",
            headers=headers,
            params={"limit": args.limit},
            timeout=10,
        )
        if resp.status_code != 200:
            print(
                f"FAILED: {resp.status_code} — {resp.text}",
                file=sys.stderr,
            )
            return 1
        events = resp.json()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if isinstance(events, dict):
        events = events.get("events", [events])

    if args.jsonl:
        output = "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events)
    else:
        output = json.dumps(events, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Exported {len(events)} events to {args.output}")
    else:
        print(output)

    return 0


# ──────────────────────────────────────────────────────────────────────
# aegis-soc-summary  (#1202)
# ──────────────────────────────────────────────────────────────────────
def soc_summary_main(argv: Optional[List[str]] = None) -> int:
    """Show SOC alert/incident summary counts."""
    parser = argparse.ArgumentParser(
        prog="aegis-soc-summary",
        description="Show AegisAgent SOC alert/incident summary.",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table)",
    )
    args = parser.parse_args(argv)

    endpoint = _endpoint()
    headers = _headers()

    try:
        resp = requests.get(f"{endpoint}/v1/soc/summary", headers=headers, timeout=5)
        if resp.status_code != 200:
            print(f"FAILED: {resp.status_code} — {resp.text}", file=sys.stderr)
            return 1
        summary = resp.json()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print(_colorize("SOC Summary", CYAN))
        print("─" * 40)
        for k, v in summary.items():
            print(f"  {k}: {v}")

    return 0


# ──────────────────────────────────────────────────────────────────────
# aegis  — unified kubectl-style dispatcher (#1202)
# ──────────────────────────────────────────────────────────────────────
_TOP_LEVEL_USAGE = """\
usage: aegis <subcommand> [options]

Subcommands:
  status            Show gateway health and stats
  freeze-agent      Freeze an agent by ID
  unfreeze-agent    Unfreeze (restore) an agent by ID
  verify-receipts   Verify a receipt chain from a JSON file
  export-audit      Export audit events as JSON/JSONL
  soc-summary       Show SOC alert/incident summary

Run `aegis <subcommand> --help` for subcommand-specific options.
"""


def _unfreeze_agent_main(argv: Optional[List[str]] = None) -> int:
    return freeze_agent_main((argv or []) + ["--unfreeze"])


def _verify_receipts_main(argv: Optional[List[str]] = None) -> int:
    # Imported lazily (rather than at module scope) purely to keep this
    # module's import-time surface minimal; there's no circular dependency —
    # verify_receipts.py never imports cli.py.
    from .verify_receipts import main as verify_receipts_main

    return verify_receipts_main(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """Unified `aegis <subcommand>` dispatcher (#1202) — kubectl-style entry
    point wrapping the existing standalone `aegis-*` scripts so a single
    `pip install aegisagent` gives one discoverable command. Each
    subcommand's underlying implementation and its standalone script are
    unchanged; this only routes argv to the right one."""
    argv = sys.argv[1:] if argv is None else argv

    if not argv:
        print(_TOP_LEVEL_USAGE, file=sys.stderr)
        return 2

    if argv[0] in ("-h", "--help"):
        print(_TOP_LEVEL_USAGE)
        return 0

    # Built per-call (not as a module-level constant) so the dispatch table
    # always reflects the current `status_main`/etc. — important for tests
    # that patch e.g. `aegisagent.cli.status_main` directly.
    subcommands = {
        "status": status_main,
        "freeze-agent": freeze_agent_main,
        "unfreeze-agent": _unfreeze_agent_main,
        "verify-receipts": _verify_receipts_main,
        "export-audit": export_audit_main,
        "soc-summary": soc_summary_main,
    }

    subcommand, rest = argv[0], argv[1:]
    handler = subcommands.get(subcommand)
    if handler is None:
        print(f"ERROR: unknown subcommand '{subcommand}'.\n", file=sys.stderr)
        print(_TOP_LEVEL_USAGE, file=sys.stderr)
        return 2

    return handler(rest)


if __name__ == "__main__":
    raise SystemExit(main())

"""CLI commands for AegisAgent SDK operational tasks.

Entry points (registered in pyproject.toml):

    aegis-status           — show gateway health + version (TASK-0182)
    aegis-freeze-agent     — freeze an agent by ID (TASK-0181)
    aegis-export-audit     — export audit events as JSON/JSONL (TASK-0180)

All commands read ``AEGIS_API_KEY`` and ``AEGIS_ENDPOINT`` from the
environment (``AEGIS_ENDPOINT`` defaults to ``http://127.0.0.1:8080``).
"""

import argparse
import json
import os
import sys
from typing import List, Optional

import requests


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
        "--json", action="store_true", dest="as_json", help="Output raw JSON"
    )
    args = parser.parse_args(argv)

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

    if args.as_json:
        print(json.dumps(result, indent=2))
    else:
        status = health.get("status", "unknown")
        version = health.get("version", "unknown")
        print(f"Gateway:  {endpoint}")
        print(f"Status:   {status}")
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
            print(f"OK: agent '{args.agent_id}' {verb}d successfully.")
            return 0
        else:
            print(
                f"FAILED: {resp.status_code} — {resp.text}",
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


if __name__ == "__main__":
    raise SystemExit(status_main())

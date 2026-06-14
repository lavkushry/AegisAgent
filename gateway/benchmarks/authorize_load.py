#!/usr/bin/env python3
"""TASK-1313: HTTP-level load test for POST /v1/authorize (stdlib fallback).

NOTE: vegeta WAS successfully installed in this sandbox
(`go install github.com/tsenart/vegeta@latest`), so
`gateway/benchmarks/authorize_load.sh` is the primary HTTP load test for this
environment. This script is kept as a portable, dependency-free alternative
for environments where neither k6 nor vegeta/go is available — it uses only
the Python standard library (`http.client` + `concurrent.futures`).

A `.k6.js` script (`authorize_load.k6.js`, untested in this sandbox — no `k6`
binary) is also provided alongside this file for environments where k6 is
preferred/available.

Usage:
    # 1. Start the gateway (binds 127.0.0.1:8080 by default):
    cargo run --manifest-path gateway/Cargo.toml &

    # 2. Run this script (registers its own tenant + bench agent):
    python3 gateway/benchmarks/authorize_load.py \\
        --gateway http://127.0.0.1:8080 \\
        --requests 200 \\
        --concurrency 10

Reports p50/p95/p99 latency (ms) and throughput (req/s) for a steady-state
allow decision (`filesystem.read_file`, `mutates_state: false`,
`trusted_internal_signed` — the policy pack permits this instantly with no
approval).
"""

from __future__ import annotations

import argparse
import http.client
import json
import statistics
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed


def _register_agent(gateway: str, tenant_id: str, agent_key: str) -> str:
    """Register a bench agent (best-effort tenant registration first) and
    return its plaintext agent_token."""
    parsed = urllib.parse.urlparse(gateway)

    # Best-effort tenant registration — ignore failure if it already exists.
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        conn.request(
            "POST",
            "/v1/tenants",
            body=json.dumps(
                {"id": tenant_id, "name": "Bench Load Tenant", "plan": "developer"}
            ),
            headers={"Content-Type": "application/json"},
        )
        conn.getresponse().read()
    except Exception:
        pass
    finally:
        conn.close()

    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        conn.request(
            "POST",
            "/v1/agents/register",
            body=json.dumps(
                {
                    "agent_key": agent_key,
                    "name": "Bench Load Agent",
                    "environment": "production",
                    "risk_tier": "high",
                }
            ),
            headers={
                "Content-Type": "application/json",
                # Agent registration is an admin/operator endpoint, authenticated
                # via TenantId::from_request_parts, which (absent JWT) accepts a
                # `Bearer tenant_<id>`-shaped token as a tenant-scoped credential.
                # This is distinct from the `X-Aegis-Tenant-ID` header used below
                # by `/v1/authorize`, which authenticates as an *agent*.
                "Authorization": f"Bearer {tenant_id}",
            },
        )
        resp = conn.getresponse()
        body = json.loads(resp.read())
        if resp.status >= 300:
            raise RuntimeError(f"agent registration failed: {resp.status} {body}")
        return body["agent_token"]
    finally:
        conn.close()


def _one_request(gateway: str, tenant_id: str, agent_token: str) -> float:
    """Issue one POST /v1/authorize call; return latency in milliseconds."""
    parsed = urllib.parse.urlparse(gateway)
    payload = json.dumps(
        {
            "agent": {"id": "bench-load-agent", "environment": "production"},
            "tool_call": {
                "tool": "filesystem",
                "action": "read_file",
                "resource": "bench.txt",
                "mutates_state": False,
                "parameters": {},
            },
            "context": {
                "source_trust": "trusted_internal_signed",
                "contains_sensitive_data": False,
            },
            "trace": {"run_id": "run_bench_load", "trace_id": "trace_bench_load"},
        }
    )
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {agent_token}",
        "X-Aegis-Tenant-ID": tenant_id,
    }

    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        start = time.perf_counter()
        conn.request("POST", "/v1/authorize", body=payload, headers=headers)
        resp = conn.getresponse()
        resp.read()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if resp.status != 200:
            raise RuntimeError(f"unexpected status {resp.status}")
        return elapsed_ms
    finally:
        conn.close()


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return float("nan")
    idx = int(round((pct / 100.0) * (len(sorted_values) - 1)))
    idx = max(0, min(idx, len(sorted_values) - 1))
    return sorted_values[idx]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", default="http://127.0.0.1:8080")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=10)
    args = parser.parse_args()

    tenant_id = "tenant_bench_load_py"
    agent_key = f"bench-load-agent-py-{int(time.time())}"

    print(f"Registering bench agent against {args.gateway} ...")
    agent_token = _register_agent(args.gateway, tenant_id, agent_key)

    print(
        f"Running {args.requests} requests at concurrency={args.concurrency} ..."
    )
    latencies: list[float] = []
    wall_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [
            pool.submit(_one_request, args.gateway, tenant_id, agent_token)
            for _ in range(args.requests)
        ]
        for fut in as_completed(futures):
            latencies.append(fut.result())
    wall_elapsed = time.perf_counter() - wall_start

    latencies.sort()
    p50 = _percentile(latencies, 50)
    p95 = _percentile(latencies, 95)
    p99 = _percentile(latencies, 99)
    mean = statistics.mean(latencies)
    throughput = len(latencies) / wall_elapsed

    print()
    print(f"requests:    {len(latencies)}")
    print(f"wall time:   {wall_elapsed:.3f}s")
    print(f"throughput:  {throughput:.1f} req/s")
    print(f"mean:        {mean:.3f} ms")
    print(f"p50:         {p50:.3f} ms")
    print(f"p95:         {p95:.3f} ms")
    print(f"p99:         {p99:.3f} ms")


if __name__ == "__main__":
    main()

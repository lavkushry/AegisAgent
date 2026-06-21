// TASK-1313: k6 HTTP load test for POST /v1/authorize.
//
// UNTESTED in the dev sandbox this was authored in — `k6` is not installed
// there (vegeta was used instead, see `authorize_load.sh`). This script is
// provided so the issue's literal "k6 or vegeta" artifact exists for any
// environment where k6 is available.
//
// Usage:
//   cargo run --manifest-path gateway/Cargo.toml &   // start the gateway
//   k6 run gateway/benchmarks/authorize_load.k6.js
//
// Env vars:
//   GATEWAY_URL   base URL of the gateway (default http://127.0.0.1:8080)
//   VUS           virtual users (default 10)
//   DURATION      test duration (default 5s)

import http from 'k6/http';
import { check } from 'k6';

const GATEWAY_URL = __ENV.GATEWAY_URL || 'http://127.0.0.1:8080';
const TENANT_ID = 'tenant_bench_load_k6';
const AGENT_KEY = `bench-load-agent-k6-${Date.now()}`;

export const options = {
  vus: Number(__ENV.VUS || 10),
  duration: __ENV.DURATION || '5s',
  thresholds: {
    // Mirrors the issue's targets (HTTP-level, includes framing overhead).
    http_req_duration: ['p(50)<10', 'p(95)<50', 'p(99)<100'],
  },
};

// k6 doesn't have a great per-VU one-time-setup story for stateful agent
// registration across distributed runs, so registration happens once in
// `setup()` and the token is shared via the returned data object.
export function setup() {
  // Best-effort tenant registration.
  http.post(
    `${GATEWAY_URL}/v1/tenants`,
    JSON.stringify({ id: TENANT_ID, name: 'Bench Load Tenant (k6)', plan: 'developer' }),
    { headers: { 'Content-Type': 'application/json' } },
  );

  const registerRes = http.post(
    `${GATEWAY_URL}/v1/agents/register`,
    JSON.stringify({
      agent_key: AGENT_KEY,
      name: 'Bench Load Agent (k6)',
      environment: 'production',
      risk_tier: 'high',
    }),
    {
      // Agent registration is tenant-authenticated via `Bearer tenant_<id>`
      // (TenantId::from_request_parts JWT fallback), distinct from the
      // `X-Aegis-Tenant-ID` + agent-token auth used by `/v1/authorize` below.
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TENANT_ID}`,
      },
    },
  );

  check(registerRes, { 'agent registered': (r) => r.status === 200 || r.status === 201 });
  const agentToken = registerRes.json('agent_token');
  return { agentToken };
}

export default function (data) {
  const payload = JSON.stringify({
    agent: { id: AGENT_KEY, environment: 'production' },
    tool_call: {
      tool: 'filesystem',
      action: 'read_file',
      resource: 'bench.txt',
      mutates_state: false,
      parameters: {},
    },
    context: { source_trust: 'trusted_internal_signed', contains_sensitive_data: false },
    trace: { run_id: 'run_bench_load_k6', trace_id: 'trace_bench_load_k6' },
  });

  const res = http.post(`${GATEWAY_URL}/v1/authorize`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${data.agentToken}`,
      'X-Aegis-Tenant-ID': TENANT_ID,
    },
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'decision is allow': (r) => r.json('decision') === 'allow',
  });
}

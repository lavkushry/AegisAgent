#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

AEGIS_URL="${AEGIS_URL:-http://127.0.0.1:8080}"
AEGIS_GRPC_PORT="${AEGIS_GRPC_PORT:-6334}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

failed=0

ok() {
  printf 'ok: %s\n' "$1"
}

warn() {
  printf 'warn: %s\n' "$1"
}

error() {
  printf 'error: %s\n' "$1"
  failed=1
}

require_command() {
  if command -v "$1" >/dev/null 2>&1; then
    ok "$1 found"
    return 0
  fi

  error "missing required command: $1"
  return 1
}

docker_ok=0
curl_ok=0
python_ok=0

if require_command docker; then
  docker_ok=1
fi

if require_command curl; then
  curl_ok=1
fi

if python_version="$("$PYTHON_BIN" --version 2>&1)"; then
  ok "Python runnable: $python_version"
  python_ok=1
else
  error "Python command is not runnable: $PYTHON_BIN"
fi

if [ "$python_ok" = "1" ]; then
  if "$PYTHON_BIN" - <<'PY'
import sys

raise SystemExit(0 if sys.version_info >= (3, 8) else 1)
PY
  then
    ok "Python version is >= 3.8"
  else
    error "Python version must be >= 3.8"
  fi
fi

if [ "$docker_ok" = "1" ]; then
  if docker compose version >/dev/null 2>&1; then
    ok "Docker Compose plugin found"
  else
    error "Docker Compose plugin is unavailable"
  fi

  if docker info >/dev/null 2>&1; then
    ok "Docker daemon is running"
  else
    error "Docker daemon is not running. Start Docker Desktop or dockerd before running make demo."
  fi

  if docker compose config >/dev/null 2>&1; then
    ok "Docker Compose configuration is valid"
  else
    error "Docker Compose configuration is invalid"
  fi
fi

if [ "$curl_ok" = "1" ] && curl -fsS "$AEGIS_URL/health" >/dev/null 2>&1; then
  ok "Aegis gateway is already healthy at $AEGIS_URL"
elif [ "$python_ok" = "1" ]; then
  port_status="$("$PYTHON_BIN" - "$AEGIS_URL" "$AEGIS_GRPC_PORT" <<'PY'
import socket
import sys
from urllib.parse import urlparse

url = urlparse(sys.argv[1])
host = url.hostname or "127.0.0.1"
rest_port = url.port or (443 if url.scheme == "https" else 80)
grpc_port = int(sys.argv[2])


def can_connect(port):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


print("REST_BUSY" if can_connect(rest_port) else "REST_AVAILABLE")
print("GRPC_BUSY" if can_connect(grpc_port) else "GRPC_AVAILABLE")
PY
)"

  case "$port_status" in
    *REST_BUSY*)
      error "REST port from AEGIS_URL ($AEGIS_URL) is in use but /health is not healthy"
      ;;
    *REST_AVAILABLE*)
      ok "REST port from AEGIS_URL ($AEGIS_URL) is available"
      ;;
  esac

  case "$port_status" in
    *GRPC_BUSY*)
      error "gRPC port $AEGIS_GRPC_PORT is already in use"
      ;;
    *GRPC_AVAILABLE*)
      ok "gRPC port $AEGIS_GRPC_PORT is available"
      ;;
  esac
else
  warn "skipping port availability checks because Python is unavailable"
fi

if [ "$failed" -ne 0 ]; then
  printf '\nAegisAgent doctor found blocking local setup issues.\n'
  exit 1
fi

printf '\nAegisAgent doctor passed. Run: make demo\n'

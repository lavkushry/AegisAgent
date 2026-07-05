#!/usr/bin/env bash
# Regenerate lib/storage/.sqlx offline query metadata (#922).
#
# Requires: cargo-sqlx CLI (`cargo install sqlx-cli --no-default-features --features sqlite`)
# and a SQLite database with all migrations applied.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_PATH="${ROOT}/db/aegisagent.db"
DB_URL="sqlite://${DB_PATH}"

mkdir -p "${ROOT}/db"

if [[ ! -f "${DB_PATH}" ]]; then
  echo "Creating ${DB_PATH} and applying migrations..."
  export DATABASE_URL="${DB_URL}"
  (cd "${ROOT}/lib/storage" && sqlx database create)
  (cd "${ROOT}/lib/storage" && sqlx migrate run)
else
  echo "Using existing ${DB_PATH}"
  export DATABASE_URL="${DB_URL}"
  (cd "${ROOT}/lib/storage" && sqlx migrate run)
fi

echo "Preparing offline query cache for aegis-storage..."
export DATABASE_URL="${DB_URL}"
(cd "${ROOT}/lib/storage" && cargo sqlx prepare -- --all-targets)

echo "Done. Commit lib/storage/.sqlx/ alongside any query changes."
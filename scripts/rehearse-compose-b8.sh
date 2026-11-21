#!/usr/bin/env bash
# CI-only disposable PostgreSQL Compose + synthetic historical upgrade rehearsal.
set -euo pipefail
if [[ "$GITHUB_ACTIONS" != true || "$CI" != true || -z "$GITHUB_RUN_ID" || -z "$RUNNER_TEMP" ]]; then
 echo "Refusing B8 outside GitHub CI" >&2
 exit 2
fi
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FULL="$ROOT/docker-compose.yml"
LEGACY="$ROOT/.compose-b8-legacy-$GITHUB_RUN_ID.yml"
WORK="$(mktemp -d "$RUNNER_TEMP/profitpilot-b8-XXXXXX")"
PROJECT="profitpilotb8$GITHUB_RUN_ID"
cleanup() {
 docker compose -p "$PROJECT" -f "$FULL" down --volumes --remove-orphans >/dev/null 2>&1 || true
 rm -f "$LEGACY"
 rm -rf "$WORK"
}
trap cleanup EXIT
export POSTGRES_ADMIN_PASSWORD="$(openssl rand -hex 32)"
export POSTGRES_APP_PASSWORD="$(openssl rand -hex 32)"
export TENANT_CONTEXT_HMAC_SECRET="$(openssl rand -hex 32)"
export CORS_ORIGIN="http://localhost:8080"
export AUTH_ISSUER="https://example.invalid/"
export AUTH_AUDIENCE="profitpilot-api"
export AUTH_JWKS_URL="https://example.invalid/keys"
printf '::add-mask::%s\n' "$POSTGRES_ADMIN_PASSWORD"
printf '::add-mask::%s\n' "$POSTGRES_APP_PASSWORD"
printf '::add-mask::%s\n' "$TENANT_CONTEXT_HMAC_SECRET"
admin_sql() {
 docker exec "$CID" psql -X -v ON_ERROR_STOP=1 -U profitpilot_admin -d profitpilot -Atqc "$1"
}
start_db() {
 local config="$1"
 docker compose -p "$PROJECT" -f "$config" up -d --no-build db
 CID="$(docker compose -p "$PROJECT" -f "$config" ps -q db)"
 [[ -n "$CID" ]] || { echo "No isolated db container" >&2; exit 1; }
}
wait_table() {
 local name="$1"
 local config="$2"
 for attempt in $(seq 1 90); do
  if [[ "$(docker inspect "$CID" --format '{{.State.Running}}' 2>/dev/null || true)" != true ]]; then
   echo "Isolated PostgreSQL exited" >&2
   exit 1
  fi
  local value
  value="$(admin_sql "SELECT to_regclass('public.$name') IS NOT NULL" 2>/dev/null || true)"
  if [[ "$value" == t && "$(docker inspect "$CID" --format '{{.State.Health.Status}}' 2>/dev/null || true)" == healthy ]]; then
   return
  fi
  sleep 2
 done
 echo "B8 timed out waiting for $name" >&2
 docker compose -p "$PROJECT" -f "$config" logs --tail 50 db >&2 || true
 exit 1
}
assert_sql() {
 local result
 result="$(admin_sql "$1")"
 [[ "$result" == "$2" ]] || { echo "B8 failed $3: got $result" >&2; exit 1; }
}
echo "B8 phase A: fresh Compose database initialisation"
start_db "$FULL"
wait_table securepay_encrypted_custody_receipts "$FULL"
assert_sql "SELECT to_regclass('private.tenant_context_keys') IS NOT NULL" t "context key schema"
assert_sql "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname='profitpilot_app'" f "runtime role privileges"
docker compose -p "$PROJECT" -f "$FULL" down --volumes --remove-orphans
echo "B8 phase B: CI-generated older Compose bootstrap"
node scripts/make-b8-legacy-compose.mjs "$LEGACY"
start_db "$LEGACY"
wait_table unified_report_snapshots "$LEGACY"
assert_sql "SELECT to_regclass('public.securepay_encrypted_custody_receipts') IS NULL" t "legacy schema boundary"
admin_sql "INSERT INTO tenants(id,legal_name) VALUES ('cccccccc-cccc-4ccc-8ccc-cccccccccccc','CI synthetic migration marker') RETURNING 1" >/dev/null
assert_sql "SELECT count(*) FROM tenants WHERE id='cccccccc-cccc-4ccc-8ccc-cccccccccccc'" 1 "baseline marker"
openssl rand -hex 32 > "$WORK/key"
openssl rand -hex 32 > "$WORK/wrong-key"
docker exec "$CID" pg_dump -U profitpilot_admin -d profitpilot --format=custom |
 gpg --batch --yes --pinentry-mode loopback --no-symkey-cache --passphrase-file "$WORK/key" --symmetric --cipher-algo AES256 --output "$WORK/legacy.dump.gpg"
test -s "$WORK/legacy.dump.gpg"
if gpg --batch --yes --pinentry-mode loopback --no-symkey-cache --passphrase-file "$WORK/wrong-key" --decrypt "$WORK/legacy.dump.gpg" >/dev/null 2>&1; then
 echo "B8 encrypted backup accepted wrong key" >&2
 exit 1
fi
gpg --batch --yes --pinentry-mode loopback --no-symkey-cache --passphrase-file "$WORK/key" --decrypt --output "$WORK/legacy.dump" "$WORK/legacy.dump.gpg"
docker exec "$CID" createdb -U profitpilot_admin profitpilot_b8_restore
docker exec -i "$CID" pg_restore -U profitpilot_admin -d profitpilot_b8_restore --exit-on-error --single-transaction < "$WORK/legacy.dump"
restored="$(docker exec "$CID" psql -X -v ON_ERROR_STOP=1 -U profitpilot_admin -d profitpilot_b8_restore -Atqc "SELECT count(*) FROM tenants WHERE id='cccccccc-cccc-4ccc-8ccc-cccccccccccc'")"
[[ "$restored" == 1 ]] || { echo "B8 restored marker mismatch" >&2; exit 1; }
echo "B8 phase C: existing volume restart cannot silently apply new migrations"
docker compose -p "$PROJECT" -f "$FULL" up -d --no-build db
CID="$(docker compose -p "$PROJECT" -f "$FULL" ps -q db)"
wait_table unified_report_snapshots "$FULL"
assert_sql "SELECT to_regclass('public.securepay_encrypted_custody_receipts') IS NULL" t "existing-volume non-migration"
assert_sql "SELECT count(*) FROM tenants WHERE id='cccccccc-cccc-4ccc-8ccc-cccccccccccc'" 1 "restart preserved source row"
echo "B8 phase D: apply only migration 025-033 to isolated, backed-up legacy database"
for n in {025..033}; do
 file="$(find database/migrations -maxdepth 1 -type f -name "$n"'_*.sql' -print)"
 count="$(find database/migrations -maxdepth 1 -type f -name "$n"'_*.sql' -print | wc -l)"
 [[ "$count" -eq 1 ]] || { echo "B8 ambiguous migration $n" >&2; exit 1; }
 docker exec -i "$CID" psql -X -v ON_ERROR_STOP=1 -U profitpilot_admin -d profitpilot < "$file" >/dev/null
done
assert_sql "SELECT to_regclass('public.securepay_encrypted_custody_receipts') IS NOT NULL" t "last migration missing"
assert_sql "SELECT count(*) FROM tenants WHERE id='cccccccc-cccc-4ccc-8ccc-cccccccccccc'" 1 "upgraded data lost"
docker compose -p "$PROJECT" -f "$FULL" restart db
wait_table securepay_encrypted_custody_receipts "$FULL"
assert_sql "SELECT count(*) FROM tenants WHERE id='cccccccc-cccc-4ccc-8ccc-cccccccccccc'" 1 "upgraded restart lost data"
visible="$(docker exec -e PGPASSWORD="$POSTGRES_APP_PASSWORD" "$CID" psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -U profitpilot_app -d profitpilot -Atqc 'SELECT count(*) FROM tenants')"
[[ "$visible" == 0 ]] || { echo "B8 RLS exposed unscoped tenant" >&2; exit 1; }
echo "B8 synthetic-only PASS: fresh boot, legacy boot, AES256 backup/wrong-key/restore, existing volume preservation, manual migration, RLS and restart"

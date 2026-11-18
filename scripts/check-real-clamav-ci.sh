#!/usr/bin/env bash
# A real daemon in a disposable CI directory, with one local synthetic hash
# signature. This does not simulate a successful fresh public CVD. Production
# acceptance separately requires the approved live fresh-signature daemon.
set -euo pipefail
umask 077
WORK="$(mktemp -d "$RUNNER_TEMP/pp-clamav-XXXXXX")"
PID=""
cleanup(){ if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$WORK"; }
trap cleanup EXIT
mkdir "$WORK/db"
printf '%s' 'ProfitPilot disposable scanner detection control 2026' > "$WORK/test-control.txt"
SIZE="$(wc -c < "$WORK/test-control.txt" | tr -d ' ')"
HASH="$(md5sum "$WORK/test-control.txt" | cut -d ' ' -f 1)"
printf '%s:%s:ProfitPilot.Synthetic.Test\n' "$HASH" "$SIZE" > "$WORK/db/synthetic.hdb"
cat > "$WORK/clamd.conf" <<EOF
Foreground yes
LocalSocket $WORK/clamd.sock
LocalSocketMode 0600
DatabaseDirectory $WORK/db
MaxThreads 2
MaxConnectionQueueLength 8
StreamMaxLength 64K
MaxScanSize 2M
MaxFileSize 1M
EOF
TZ=UTC clamd --config-file="$WORK/clamd.conf" > "$WORK/clamd.log" 2>&1 &
PID=$!
for _ in $(seq 1 30); do
  test -d "$WORK/db"
  if [ -S "$WORK/clamd.sock" ]; then break; fi
  kill -0 "$PID"
  sleep 1
done
test -S "$WORK/clamd.sock"
CLAMAV_TEST_SOCKET="$WORK/clamd.sock" node --test tests/clamav-engine.integration.test.js

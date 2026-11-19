#!/usr/bin/env bash
# Use the actual authenticated distribution's ClamAV installation and
# current official definitions. This is an ephemeral CI daemon, not a
# production deployment. No freshness bypass or substitute test signatures.
set -euo pipefail
trap 'echo "Scanner acceptance preparation failed at line $LINENO" >&2' ERR
umask 077
WORK="$(mktemp -d /tmp/pp-clamav-XXXXXX)"
PID=""
cleanup(){ if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$WORK"; }
trap cleanup EXIT
# Ensure the distro updater has completed all three official databases.
# Current VERSION alone does not establish that main and bytecode exist.
sudo freshclam --stdout
test -d /var/lib/clamav
mkdir "$WORK/db"
for name in main daily bytecode; do
  selected=""
  # An incremental CLD may coexist with the original CVD. Prefer the
  # official updated CLD; freshness is subsequently checked by the API.
  for extension in cld cvd; do
    candidate="/var/lib/clamav/$name.$extension"
    if sudo test -f "$candidate"; then
      sudo test ! -L "$candidate"
      selected="$candidate"
      break
    fi
  done
  if [ -z "$selected" ]; then
    echo "Required official signature database missing: $name" >&2
    exit 1
  fi
  sudo install -m 0600 -o "$(id -u)" -g "$(id -g)" "$selected" "$WORK/db/"
  echo "Prepared official signature database: $(basename "$selected")"
done
cat > "$WORK/clamd.conf" <<EOF
Foreground yes
LocalSocket $WORK/clamd.sock
LocalSocketMode 0600
DatabaseDirectory $WORK/db
MaxThreads 2
StreamMaxLength 64K
EOF
TZ=UTC clamd --config-file="$WORK/clamd.conf" > "$WORK/clamd.log" 2>&1 &
PID=$!
for _ in $(seq 1 60); do
  if [ -S "$WORK/clamd.sock" ]; then break; fi
  if ! kill -0 "$PID" 2>/dev/null; then cat "$WORK/clamd.log"; exit 1; fi
  sleep 1
done
if [ ! -S "$WORK/clamd.sock" ]; then cat "$WORK/clamd.log"; exit 1; fi
CLAMAV_TEST_SOCKET="$WORK/clamd.sock" node --test tests/clamav-engine.integration.test.js
CLAMAV_SOCKET_PATH="$WORK/clamd.sock" node scripts/check-live-scanner.js

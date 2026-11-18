#!/usr/bin/env bash
# Use the actual authenticated distribution's ClamAV installation and
# current official definitions. This is an ephemeral CI daemon, not a
# production deployment. No freshness bypass or substitute test signatures.
set -euo pipefail
umask 077
WORK="$(mktemp -d /tmp/pp-clamav-XXXXXX)"
PID=""
cleanup(){ if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$WORK"; }
trap cleanup EXIT
# Freshclam's distribution setup may already have the current official
# database; refresh only if the required version is missing or stale.
if ! sudo clamd --version | node -e 'let s="";process.stdin.on("data",b=>s+=b);process.stdin.on("end",async()=>{const {signaturesFresh}=await import("./server/clamav.js");if(!signaturesFresh(s.trim()))process.exitCode=1})'; then
  sudo freshclam --stdout
fi
test -d /var/lib/clamav
# The distro freshclam user owns signature files. Copy only the official
# database files into a private, runner-owned directory; never broaden
# the system database permissions or run the scanner daemon as root.
mkdir "$WORK/db"
for name in main daily bytecode; do
  selected=""
  for extension in cvd cld; do
    candidate="/var/lib/clamav/$name.$extension"
    if sudo test -f "$candidate"; then
      test -z "$selected"
      sudo test ! -L "$candidate"
      selected="$candidate"
    fi
  done
  test -n "$selected"
  sudo install -m 0600 -o "$(id -u)" -g "$(id -g)" "$selected" "$WORK/db/"
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

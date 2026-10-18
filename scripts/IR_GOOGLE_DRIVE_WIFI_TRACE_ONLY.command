#!/bin/zsh
# Stable entrypoint. Install once at ~/Downloads/IR_GOOGLE_DRIVE_WIFI_TRACE_ONLY.command.
# Runner updates remotely; entrypoint itself never needs a versioned filename.
set -euo pipefail
PY="$HOME/Library/Application Support/ESP Hardware Dev Console/repo/.venv/bin/python"
[[ -x "$PY" ]] || { print -u2 "BLOCKED: existing ESP Python missing"; exit 2; }
"$PY" -c 'import serial' >/dev/null 2>&1 ||
  { print -u2 "BLOCKED: pyserial missing in existing Mac environment"; exit 2; }

# Supports Google Drive/GAS published endpoint with IR_RUNNER_URL when available.
# Default is GitHub raw HTTPS (NOT GitHub REST API, no gh login, no rate-limited API).
URL="${IR_RUNNER_URL:-https://raw.githubusercontent.com/mokumaisancho/esp32c3-ir-remote/fix/rmt-idf-error-diagnostics/scripts/wifi_trace_runner.py}"
case "$URL" in
  https://*) ;;
  *) print -u2 "BLOCKED: HTTPS runner URL required"; exit 2;;
esac
TMP="$(mktemp -d /tmp/ir-wifi-runner.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
curl --fail --location --silent --show-error --connect-timeout 8 --max-time 25 \
  --retry 2 "$URL" -o "$TMP/runner.py" ||
  { print -u2 "BLOCKED: Cannot fetch latest runner; local launcher unchanged"; exit 2; }
[[ -s "$TMP/runner.py" ]] || { print -u2 "BLOCKED: Empty runner"; exit 2; }
"$PY" -m py_compile "$TMP/runner.py" ||
  { print -u2 "BLOCKED: Downloaded runner syntax invalid"; exit 2; }
echo "REMOTE_RUNNER_READY (Mac file unchanged)"
exec "$PY" "$TMP/runner.py"

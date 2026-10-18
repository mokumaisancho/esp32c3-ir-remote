#!/bin/zsh
# One-time USB flash of a pinned, CI-PASS firmware; backs up all existing flash first.
set -euo pipefail

REPO="mokumaisancho/esp32c3-ir-remote"
RUN_ID="39088472851"
PORT="/dev/cu.usbmodem101"
BASE="$HOME/Library/Application Support/ESP Hardware Dev Console"
BACKUPS="$BASE/backups/esp32c3-ir-remote"
WORK="$(mktemp -d /tmp/esp32c3-ir-flash.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "BLOCKED: $1" >&2; exit 2; }

[[ "$(uname -s)" == "Darwin" ]] || fail "macOS only"
command -v gh >/dev/null || fail "GitHub CLI gh missing"
[[ -c "$PORT" ]] || fail "Expected USB-JTAG serial device not found: $PORT"
gh auth status >/dev/null 2>&1 || fail "GitHub authentication missing"

echo "[1/5] Downloading CI-PASS firmware"
mkdir -p "$WORK/artifact"
gh run download "$RUN_ID" -R "$REPO" -n esp32c3-ir-remote-firmware -D "$WORK/artifact" \
  || fail "Firmware artifact unavailable"
cd "$WORK/artifact"
for file in bootloader.bin partitions.bin firmware.bin SHA256SUMS.txt; do
  [[ -s "$file" ]] || fail "Missing artifact: $file"
done
shasum -a 256 -c SHA256SUMS.txt || fail "Artifact SHA256 mismatch"

# Search known ESP Hardware Dev Console Python environments before installing.
typeset -a TOOL
TOOL=()
for python in \
  "$BASE/repo/.venv/bin/python" \
  "$BASE/repo/venv/bin/python" \
  "$BASE/.venv/bin/python" \
  /opt/homebrew/bin/python3 \
  /usr/local/bin/python3 \
  "$(command -v python3)"; do
  if [[ -x "$python" ]] && "$python" -c 'import esptool' >/dev/null 2>&1; then
    TOOL=("$python" "-m" "esptool")
    break
  fi
done
if (( ${#TOOL[@]} == 0 )); then
  echo "[2/5] Installing isolated esptool only (no PlatformIO)"
  VENV="$BASE/tools/esptool-only"
  if [[ ! -x "$VENV/bin/python" ]]; then
    python3 -m venv "$VENV" || fail "Could not create esptool-only environment"
  fi
  "$VENV/bin/python" -m pip install --no-cache-dir -q 'esptool>=5.0,<6' \
    || fail "Could not install esptool"
  TOOL=("$VENV/bin/python" "-m" "esptool")
fi

echo "[2/5] Verifying USB-connected ESP32-C3"
"${TOOL[@]}" --chip esp32c3 --port "$PORT" flash-id || fail "ESP32-C3 not detected"

# Never bypass chip security or erase the entire flash.
echo "[3/5] Backing up entire flash before first write"
mkdir -p "$BACKUPS"
BACKUP="$BACKUPS/pre-ir-$(date +%Y%m%dT%H%M%S).bin"
"${TOOL[@]}" --chip esp32c3 --port "$PORT" read-flash 0 ALL "$BACKUP" \
  || fail "Flash backup failed; nothing has been written"
[[ -s "$BACKUP" ]] || fail "Flash backup empty"
chmod 600 "$BACKUP"
shasum -a 256 "$BACKUP" > "$BACKUP.sha256"
chmod 600 "$BACKUP.sha256"
echo "BACKUP=$BACKUP"

echo "[4/5] Programming verified firmware at CI-confirmed offsets"
"${TOOL[@]}" --chip esp32c3 --port "$PORT" write-flash \
  0x0 bootloader.bin 0x8000 partitions.bin 0x10000 firmware.bin \
  || fail "Flash failed; restore possible from backup"

echo "[5/5] FLASH_DONE"
echo "SETUP_WIFI=ESP32C3-IR-Setup"
echo "SETUP_PASSWORD=esp32ir35"
echo "WEB_UI=http://192.168.4.1/"
echo "BACKUP=$BACKUP"

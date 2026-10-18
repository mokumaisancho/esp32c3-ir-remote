#!/bin/zsh
# One-time USB flash of a pinned, CI-PASS firmware; backs up all existing flash first.
set -euo pipefail

REPO="mokumaisancho/esp32c3-ir-remote"
RUN_ID="39099272784"
PORT="" # Determined after ESP32-C3 identification; never assume tty suffix
BASE="$HOME/Library/Application Support/ESP Hardware Dev Console"
BACKUPS="$BASE/backups/esp32c3-ir-remote"
WORK="$(mktemp -d /tmp/esp32c3-ir-flash.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "BLOCKED: $1" >&2; exit 2; }

[[ "$(uname -s)" == "Darwin" ]] || fail "macOS only"
command -v gh >/dev/null || fail "GitHub CLI gh missing"
gh auth status >/dev/null 2>&1 || fail "GitHub authentication missing"

echo "[1/5] Downloading CI-PASS firmware"
mkdir -p "$WORK/artifact"
gh run download "$RUN_ID" -R "$REPO" -n esp32c3-ir-remote-firmware -D "$WORK/artifact" \
  || fail "Firmware artifact unavailable"
cd "$WORK/artifact"
for file in bootloader.bin partitions.bin boot_app0.bin firmware.bin SHA256SUMS.txt FLASH_LAYOUT.txt; do
  [[ -s "$file" ]] || fail "Missing artifact: $file"
done
# CI computes SHA256 from inside its parent directory, so the manifest
# contains "artifact/<file>" although gh extracts ZIP members into this directory.
# Keep the pinned hashes intact; strip only that exact fixed path prefix.
for file in bootloader.bin partitions.bin boot_app0.bin firmware.bin firmware.elf FLASH_LAYOUT.txt; do
  grep -Fq "  artifact/$file" SHA256SUMS.txt ||
    fail "Checksum manifest does not contain expected artifact/$file entry"
done
sed 's@  artifact/@  @' SHA256SUMS.txt | shasum -a 256 -c - ||
  fail "Firmware file hashes do not match CI SHA256 manifest"

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
  if [[ -x "$python" ]] && "$python" -c 'import importlib.metadata as m; assert m.version("esptool").split(".")[0] == "5"' >/dev/null 2>&1; then
    TOOL=("$python" "-m" "esptool")
    break
  fi
done
if (( ${#TOOL[@]} == 0 )); then
  # Reuse the Mac-proven esptool installation route from esp32-csi-e2e,
  # evidence/mac_usb_probe/run_20261016T003152238378Z_11692.json.
  # A default pip package mirror previously returned "from versions: none".
  echo "[2/5] Mac-proven isolated official PyPI esptool 5.5.0"
  VENV="$WORK/esptool-venv"
  python3 -m venv "$VENV" || fail "Isolated Python virtual environment unavailable"
  PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    "$VENV/bin/python" -m pip --isolated install --no-input \
    --index-url https://pypi.org/simple --timeout 15 --retries 2 \
    'esptool==5.5.0' || fail "Official PyPI esptool installation failed"
  "$VENV/bin/python" -c 'import importlib.metadata as m; assert m.version("esptool") == "5.5.0"' \
    || fail "Verified esptool package version mismatch"
  TOOL=("$VENV/bin/python" "-m" "esptool")
fi
echo "[2/5] Auto-discovering and identifying USB-connected ESP32-C3"

# zsh null_glob avoids a fatal NOMATCH when a serial device family is absent.
setopt NULL_GLOB
typeset -a candidates matches
if [[ -n "${IR_FLASH_PORT:-}" ]]; then
  candidates=("$IR_FLASH_PORT")
else
  candidates=(
    /dev/cu.usbmodem*
    /dev/cu.usbserial*
    /dev/cu.wchusbserial*
    /dev/cu.SLAB_USBtoUART*
  )
fi
unsetopt NULL_GLOB

if (( ${#candidates[@]} == 0 )); then
  echo "No USB serial device found. Detected /dev/cu.* entries:" >&2
  ls /dev/cu.* 2>/dev/null || true
  fail "ESP32-C3 is not enumerated. Reconnect USB data cable and check the device."
fi

matches=()
for candidate in "${candidates[@]}"; do
  [[ -c "$candidate" ]] || continue
  echo "PROBING=$candidate"
  # 'auto' discovers the actual chip, so an unrelated ESP32/S3 is not accepted.
  probe_output="$("${TOOL[@]}" --chip auto --port "$candidate" flash-id 2>&1)" || {
    echo "SKIP: $candidate did not pass esptool identification"
    continue
  }
  if print -r -- "$probe_output" | grep -Eiq 'ESP32-C3'; then
    matches+=("$candidate")
    echo "MATCH_ESP32C3=$candidate"
  else
    echo "SKIP: $candidate is not an ESP32-C3"
  fi
done

if (( ${#matches[@]} == 0 )); then
  fail "No ESP32-C3 identified among USB serial candidates. No firmware has been written."
fi
if (( ${#matches[@]} != 1 )); then
  printf 'AMBIGUOUS_ESP32C3_PORTS=%s\n' "${matches[*]}" >&2
  fail "Multiple ESP32-C3 devices detected; set IR_FLASH_PORT to the intended port."
fi
PORT="${matches[1]}"
echo "SELECTED_PORT=$PORT"
# Recheck specifically as ESP32-C3 immediately before backup and flashing.
"${TOOL[@]}" --chip esp32c3 --port "$PORT" flash-id ||
  fail "Selected ESP32-C3 disconnected or failed verification"

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
  0x0 bootloader.bin 0x8000 partitions.bin 0xE000 boot_app0.bin 0x10000 firmware.bin \
  || fail "Flash failed; restore possible from backup"

echo "[5/5] FLASH_DONE"
echo "SETUP_WIFI=ESP32C3-IR-Setup"
echo "SETUP_PASSWORD=esp32ir35"
echo "WEB_UI=http://192.168.4.1/"
echo "BACKUP=$BACKUP"

#!/bin/zsh
# One-time USB flash of a pinned, CI-PASS firmware; backs up all existing flash first.
set -euo pipefail

REPO="mokumaisancho/esp32c3-ir-remote"
RUN_ID="${IR_RUN_ID:?IR_RUN_ID is required}"
EXPECTED_SHA="${IR_SOURCE_SHA:?IR_SOURCE_SHA is required}"
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
for file in bootloader.bin partitions.bin boot_app0.bin firmware.bin SHA256SUMS.txt FLASH_LAYOUT.txt SOURCE_SHA.txt; do
  [[ -s "$file" ]] || fail "Missing artifact: $file"
done
# CI computes SHA256 from inside its parent directory, so the manifest
# contains "artifact/<file>" although gh extracts ZIP members into this directory.
# Keep the pinned hashes intact; strip only that exact fixed path prefix.
for file in bootloader.bin partitions.bin boot_app0.bin firmware.bin firmware.elf FLASH_LAYOUT.txt SOURCE_SHA.txt; do
  grep -Fq "  artifact/$file" SHA256SUMS.txt ||
    fail "Checksum manifest does not contain expected artifact/$file entry"
done
sed 's@  artifact/@  @' SHA256SUMS.txt | shasum -a 256 -c - ||
  fail "Firmware file hashes do not match CI SHA256 manifest"

[[ "$(cat SOURCE_SHA.txt)" == "$EXPECTED_SHA" ]] || fail "Source SHA mismatch; do not flash stale firmware"
echo "VERIFIED_SOURCE_SHA=$EXPECTED_SHA"

# Reuse an installed esptool. Never pip-install during flash: low-disk-safe.
typeset -a TOOL
TOOL=()
for python in \
  "$BASE/repo/.venv/bin/python" \
  "$BASE/repo/venv/bin/python" \
  "$BASE/.venv/bin/python" \
  "$HOME/.platformio/penv/bin/python" \
  "$HOME/.platformio/penv/bin/python3" \
  /opt/homebrew/bin/python3 \
  /usr/local/bin/python3 \
  "$(command -v python3)"; do
  if [[ -x "$python" ]] && "$python" -c 'import esptool' >/dev/null 2>&1; then
    TOOL=("$python" "-m" "esptool")
    break
  fi
done
if (( ${#TOOL[@]} == 0 )); then
  for cmd in "$HOME/.platformio/penv/bin/esptool" "$HOME/.platformio/penv/bin/esptool.py" \
             /opt/homebrew/bin/esptool /opt/homebrew/bin/esptool.py \
             /usr/local/bin/esptool /usr/local/bin/esptool.py; do
    if [[ -x "$cmd" ]] && "$cmd" version >/dev/null 2>&1; then
      TOOL=("$cmd")
      break
    fi
  done
fi
if (( ${#TOOL[@]} == 0 )); then
  # The previous temporary venv was removed after each flash. Install once
  # into the EXISTING application venv, without pip cache, and reuse thereafter.
  PERSISTENT_PY="$BASE/repo/.venv/bin/python"
  [[ -x "$PERSISTENT_PY" ]] || fail "Persistent app Python venv not found"
  "$PERSISTENT_PY" -m pip --version >/dev/null 2>&1 ||
    fail "Persistent Python environment has no pip"
  # Minimum free disk: 512 MiB. Do not attempt package installs on full disk.
  FREE_KIB="$(df -Pk "$BASE" | awk 'NR==2 {print $4}')"
  [[ "$FREE_KIB" == <-> ]] || fail "Cannot determine free disk space"
  (( FREE_KIB >= 524288 )) ||
    fail "Less than 512 MiB free; esptool installation skipped safely"
  echo "[2/5] Installing esptool 5.5.0 once into existing application venv (no cache)"
  PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    "$PERSISTENT_PY" -m pip --isolated install --no-input --no-cache-dir \
      --index-url https://pypi.org/simple --timeout 15 --retries 2 \
      'esptool==5.5.0' || fail "Persistent esptool install failed; flash not started"
  "$PERSISTENT_PY" -c 'import esptool' >/dev/null 2>&1 ||
    fail "Installed esptool cannot be imported"
  TOOL=("$PERSISTENT_PY" "-m" "esptool")
fi
echo "REUSED_ESPTOOL=${TOOL[*]}"
ESPT_HELP="$("${TOOL[@]}" --help 2>&1)" || fail "Existing esptool cannot run"
if print -r -- "$ESPT_HELP" | grep -q 'read-flash'; then
  READ_FLASH=read-flash
  WRITE_FLASH=write-flash
  FLASH_ID=flash-id
elif print -r -- "$ESPT_HELP" | grep -q 'read_flash'; then
  READ_FLASH=read_flash
  WRITE_FLASH=write_flash
  FLASH_ID=flash_id
else
  fail "Existing esptool does not support expected flash commands"
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
  probe_output="$("${TOOL[@]}" --chip auto --port "$candidate" "$FLASH_ID" 2>&1)" || {
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
"${TOOL[@]}" --chip esp32c3 --port "$PORT" "$FLASH_ID" ||
  fail "Selected ESP32-C3 disconnected or failed verification"

# Never bypass chip security or erase the entire flash.
echo "[3/5] Backing up entire flash before first write"
mkdir -p "$BACKUPS"
BACKUP="$BACKUPS/pre-ir-$(date +%Y%m%dT%H%M%S).bin"
"${TOOL[@]}" --chip esp32c3 --port "$PORT" "$READ_FLASH" 0 ALL "$BACKUP" \
  || fail "Flash backup failed; nothing has been written"
[[ -s "$BACKUP" ]] || fail "Flash backup empty"
chmod 600 "$BACKUP"
shasum -a 256 "$BACKUP" > "$BACKUP.sha256"
chmod 600 "$BACKUP.sha256"
echo "BACKUP=$BACKUP"

echo "[4/5] Programming verified firmware at CI-confirmed offsets"
"${TOOL[@]}" --chip esp32c3 --port "$PORT" "$WRITE_FLASH" \
  0x0 bootloader.bin 0x8000 partitions.bin 0xE000 boot_app0.bin 0x10000 firmware.bin \
  || fail "Flash failed; restore possible from backup"

echo "[5/5] Read back flashed application and compare SHA256"
FIRMWARE_BYTES="$(stat -f %z firmware.bin)"
"${TOOL[@]}" --chip esp32c3 --port "$PORT" "$READ_FLASH" 0x10000 "$FIRMWARE_BYTES" "$WORK/firmware.readback.bin" \
  || fail "Firmware readback failed (flash written but unverified)"
[[ "$(shasum -a 256 firmware.bin | awk '{print $1}')" == "$(shasum -a 256 "$WORK/firmware.readback.bin" | awk '{print $1}')" ]] \
  || fail "Firmware flash readback SHA256 MISMATCH"
echo "FLASH_READBACK_SHA256_PASS"
echo "[5/5] FLASH_DONE"
echo "VERIFIED_FIRMWARE_SHA256=$(shasum -a 256 firmware.bin | cut -d\  -f1)"
echo "SETUP_WIFI=ESP32C3-IR-Setup"
echo "SETUP_PASSWORD=esp32ir35"
echo "WEB_UI=http://192.168.4.1/"
echo "BACKUP=$BACKUP"

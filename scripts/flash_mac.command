#!/bin/zsh
# One-time USB flash of a pinned, CI-PASS firmware; backs up all existing flash first.
set -euo pipefail

REPO="mokumaisancho/esp32c3-ir-remote"
RUN_ID="39092905791"
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
for file in bootloader.bin partitions.bin firmware.bin SHA256SUMS.txt; do
  [[ -s "$file" ]] || fail "Missing artifact: $file"
done
# CI computes SHA256 from inside its parent directory, so the manifest
# contains "artifact/<file>" although gh extracts ZIP members into this directory.
# Keep the pinned hashes intact; strip only that exact fixed path prefix.
for file in bootloader.bin partitions.bin firmware.bin firmware.elf; do
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
  # Espressif publishes notarized self-contained macOS arm64 binaries on
  # GitHub Releases. Reuse that official tool without PyPI/PlatformIO/pip.
  # Digest is from the GitHub release API asset digest (v5.4.0).
  echo "[2/5] Downloading SHA256-pinned official standalone esptool (no pip)"
  [[ "$(uname -m)" == "arm64" ]] || fail "Unsupported Mac CPU for pinned standalone esptool"
  ESPSRC="espressif/esptool"
  ESPTAG="v5.4.0"
  ESPTAR="esptool-v5.4.0-macos-arm64.tar.gz"
  ESPSHA="ba332671130939e2e6db90c2784488f7e62a1459b0fe3c5ec66e9a366821de7a"
  mkdir -p "$WORK/tools"
  gh release download "$ESPTAG" -R "$ESPSRC" -p "$ESPTAR" -D "$WORK/tools" \
    || fail "Could not download Espressif official esptool release"
  print -r -- "$ESPSHA  $WORK/tools/$ESPTAR" | shasum -a 256 -c - \
    || fail "Official esptool release SHA256 mismatch"
  # The trusted archive is still checked for unsafe member paths before extraction.
  tar -tzf "$WORK/tools/$ESPTAR" > "$WORK/tools/esptool-archive-list" \
    || fail "Invalid official esptool archive"
  if grep -Eq '(^/|(^|/)\.\.(/|$))' "$WORK/tools/esptool-archive-list"; then
    fail "Unsafe path in official esptool archive"
  fi
  tar -xzf "$WORK/tools/$ESPTAR" -C "$WORK/tools" \
    || fail "Could not unpack official esptool"
  typeset -a esptool_bins
  esptool_bins=("${(@f)$(find "$WORK/tools" -type f -name esptool -maxdepth 4 -print)}")
  (( ${#esptool_bins[@]} == 1 )) || fail "Standalone esptool executable was not uniquely found"
  chmod u+x "${esptool_bins[1]}"
  ("${esptool_bins[1]}" version || "${esptool_bins[1]}" --version) 2>&1 | grep -Fq "5.4.0" \
    || fail "Standalone esptool version mismatch"
  TOOL=("${esptool_bins[1]}")
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
  0x0 bootloader.bin 0x8000 partitions.bin 0x10000 firmware.bin \
  || fail "Flash failed; restore possible from backup"

echo "[5/5] FLASH_DONE"
echo "SETUP_WIFI=ESP32C3-IR-Setup"
echo "SETUP_PASSWORD=esp32ir35"
echo "WEB_UI=http://192.168.4.1/"
echo "BACKUP=$BACKUP"

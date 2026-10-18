#!/bin/zsh
# Pinned official Espressif macOS ARM64 standalone binary; no pip, Python, PlatformIO.
# Entire existing flash is backed up and SHA256-verified before any write.
set -euo pipefail
REPO="mokumaisancho/esp32c3-ir-remote"
RUN_ID="39092905791"
ESPTOOL_TAG="v5.6.0"
ESPTOOL_ASSET="esptool-v5.6.0-macos-arm64.tar.gz"
ESPTOOL_ASSET_SHA256="08a58829a3f14bb08f2e39f4cad48dcb14b7000384268e7f06689836332d6e25"
BACKUPS="$HOME/Library/Application Support/ESP Hardware Dev Console/backups/esp32c3-ir-remote"
WORK="$(mktemp -d /tmp/esp32c3-ir-standalone.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "BLOCKED: $1" >&2; exit 2; }
[[ "$(uname -s)" == "Darwin" ]] || fail "Only macOS is supported"
[[ "$(uname -m)" == "arm64" ]] || fail "Only pinned Mac Apple Silicon binary is supported"
command -v gh >/dev/null || fail "GitHub CLI missing"
gh auth status >/dev/null 2>&1 || fail "GitHub CLI authentication missing"

echo "[1/5] Download official pinned standalone esptool and CI firmware"
mkdir -p "$WORK/tool" "$WORK/artifact"
gh release download "$ESPTOOL_TAG" -R espressif/esptool -p "$ESPTOOL_ASSET" -D "$WORK/tool" || fail "Official esptool asset unavailable"
ACTUAL=$(shasum -a 256 "$WORK/tool/$ESPTOOL_ASSET" | awk '{print $1}')
[[ "$ACTUAL" == "$ESPTOOL_ASSET_SHA256" ]] || fail "Official esptool asset SHA256 mismatch"
mkdir -p "$WORK/tool/unpacked"
tar -xzf "$WORK/tool/$ESPTOOL_ASSET" -C "$WORK/tool/unpacked" || fail "Unable to extract esptool"
ESPT="$(find "$WORK/tool/unpacked" -type f -name esptool -print -quit)"
[[ -n "$ESPT" && -f "$ESPT" ]] || fail "Official standalone esptool executable not found"
chmod u+x "$ESPT"
"$ESPT" version | grep -Fq '5.6.0' || fail "Standalone esptool version mismatch"

gh run download "$RUN_ID" -R "$REPO" -n esp32c3-ir-remote-firmware -D "$WORK/artifact" || fail "Pinned firmware unavailable"
cd "$WORK/artifact"
for file in bootloader.bin partitions.bin boot_app0.bin firmware.bin SHA256SUMS.txt FLASH_LAYOUT.txt; do
  [[ -s "$file" ]] || fail "Missing CI artifact: $file"
done
sed 's@  artifact/@  @' SHA256SUMS.txt | shasum -a 256 -c - || fail "Firmware SHA256 mismatch"
for entry in "0x0000 bootloader.bin" "0x8000 partitions.bin" "0xE000 boot_app0.bin" "0x10000 firmware.bin"; do
  grep -Fxq "$entry" FLASH_LAYOUT.txt || fail "Firmware offset mismatch"
done

echo "[2/5] Identify exactly one serial ESP32-C3"
setopt NULL_GLOB
typeset -a candidates matches
candidates=(/dev/cu.usbmodem* /dev/cu.usbserial* /dev/cu.wchusbserial* /dev/cu.SLAB_USBtoUART*)
unsetopt NULL_GLOB
(( ${#candidates[@]} >= 1 )) || fail "No USB serial ports; no writes performed"
matches=()
for p in "${candidates[@]}"; do
  [[ -c "$p" ]] || continue
  if out="$("$ESPT" --chip auto --port "$p" flash-id 2>&1)"; then
    if print -r -- "$out" | grep -Eiq 'ESP32-C3'; then
      matches+=("$p")
      echo "MATCH_ESP32C3=$p"
    fi
  fi
done
(( ${#matches[@]} == 1 )) || fail "Ambiguous or absent ESP32-C3 USB serial port; found ${#matches[@]}"
PORT="${matches[1]}"
echo "SELECTED_PORT=$PORT"
"$ESPT" --chip esp32c3 --port "$PORT" flash-id || fail "ESP32-C3 identity recheck failed"

echo "[3/5] Back up ALL flash bytes and validate SHA256"
mkdir -p "$BACKUPS"
chmod 700 "$BACKUPS"
BACKUP="$BACKUPS/pre-ir-standalone-$(date -u +%Y%m%dT%H%M%SZ).bin"
"$ESPT" --chip esp32c3 --port "$PORT" read-flash 0 ALL "$BACKUP" || fail "Full flash backup failed, firmware not written"
[[ -s "$BACKUP" ]] || fail "Backup is empty"
SIZE="$(stat -f %z "$BACKUP")"
(( SIZE >= 2097152 && SIZE <= 33554432 && SIZE % 4096 == 0 )) || fail "Backup size invalid: $SIZE"
chmod 600 "$BACKUP"
shasum -a 256 "$BACKUP" > "$BACKUP.sha256"
chmod 600 "$BACKUP.sha256"
shasum -a 256 -c "$BACKUP.sha256" || fail "Backup hash verification failed"
echo "BACKUP=$BACKUP"
echo "BACKUP_BYTES=$SIZE"

echo "[4/5] Flash all CI images with official standalone esptool"
"$ESPT" --chip esp32c3 --port "$PORT" write-flash \
  0x0 bootloader.bin \
  0x8000 partitions.bin \
  0xE000 boot_app0.bin \
  0x10000 firmware.bin || fail "Write failed, original backup saved at $BACKUP"

echo "[5/5] FLASH_DONE"
echo "SETUP_WIFI=ESP32C3-IR-Setup"
echo "SETUP_PASSWORD=esp32ir35"
echo "WEB_UI=http://192.168.4.1/"
echo "BACKUP=$BACKUP"

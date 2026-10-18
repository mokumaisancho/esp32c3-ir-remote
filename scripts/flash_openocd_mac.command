#!/bin/zsh
# Reuse proven ESP32-C3 USB-JTAG OpenOCD, no pip, esptool, or PlatformIO.
# Exactly one pinned CI artifact; full readback is mandatory before any writes.
set -euo pipefail
REPO="mokumaisancho/esp32c3-ir-remote"
RUN_ID="39092905791"
BASE="$HOME/Library/Application Support/ESP Hardware Dev Console"
BACKUPS="$BASE/backups/esp32c3-ir-remote"
OPENOCD="$BASE/tools/openocd-esp32/bin/openocd"
SCRIPTS="$BASE/tools/openocd-esp32/share/openocd/scripts"
WORK="$(mktemp -d /tmp/esp32c3-ir-openocd.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "BLOCKED: $1" >&2; exit 2; }
[[ "$(uname -s)" == "Darwin" ]] || fail "macOS only"
command -v gh >/dev/null || fail "GitHub CLI not installed"
gh auth status >/dev/null 2>&1 || fail "GitHub authentication missing"
[[ -x "$OPENOCD" && -f "$SCRIPTS/target/esp32c3.cfg" && -f "$SCRIPTS/interface/esp_usb_jtag.cfg" ]] || fail "Proven ESP32-C3 OpenOCD missing"
echo "[1/5] CI-PASS firmware download"
mkdir -p "$WORK/artifact"
gh run download "$RUN_ID" -R "$REPO" -n esp32c3-ir-remote-firmware -D "$WORK/artifact" || fail "CI artifact unavailable"
cd "$WORK/artifact"
for file in bootloader.bin partitions.bin boot_app0.bin firmware.bin SHA256SUMS.txt FLASH_LAYOUT.txt; do
  [[ -s "$file" ]] || fail "Missing CI file: $file"
done
sed 's@  artifact/@  @' SHA256SUMS.txt | shasum -a 256 -c - || fail "CI SHA256 mismatch"
for entry in "0x0000 bootloader.bin" "0x8000 partitions.bin" "0xE000 boot_app0.bin" "0x10000 firmware.bin"; do
  grep -Fxq "$entry" FLASH_LAYOUT.txt || fail "CI flash layout mismatch: $entry"
done
echo "[2/5] ESP32-C3 JTAG identity and full-flash backup"
mkdir -p "$BACKUPS"
chmod 700 "$BACKUPS"
BACKUP="$BACKUPS/pre-ir-openocd-$(date -u +%Y%m%dT%H%M%SZ).bin"
# TCL braces preserve the spaces in the backup filename.
"$OPENOCD" -s "$SCRIPTS" -f interface/esp_usb_jtag.cfg -f target/esp32c3.cfg \
  -c "init" -c "halt" -c "flash probe 0" -c "flash read_bank 0 {$BACKUP}" -c "shutdown" > "$WORK/backup.log" 2>&1 || {
    cat "$WORK/backup.log" >&2
    fail "Flash read_bank failed. No firmware written."
  }
grep -Fq "JTAG tap: esp32c3.tap0 tap/device found" "$WORK/backup.log" || fail "Target is not verified ESP32-C3"
[[ -s "$BACKUP" ]] || fail "OpenOCD created empty backup"
SIZE=$(stat -f %z "$BACKUP") || fail "Cannot stat backup"
(( SIZE >= 2097152 && SIZE <= 33554432 && SIZE % 4096 == 0 )) || fail "Full-flash backup size outside safe bounds: $SIZE"
chmod 600 "$BACKUP"
shasum -a 256 "$BACKUP" > "$BACKUP.sha256"
chmod 600 "$BACKUP.sha256"
shasum -a 256 -c "$BACKUP.sha256" || fail "Backup SHA256 validation failed"
echo "BACKUP=$BACKUP"
echo "BACKUP_BYTES=$SIZE"
echo "[3/5] Program verified CI images, including OTA boot_app0"
for entry in "bootloader.bin 0x0" "partitions.bin 0x8000" "boot_app0.bin 0xE000" "firmware.bin 0x10000"; do
  file="${entry%% *}"
  offset="${entry##* }"
  echo "PROGRAM=${file}@${offset}"
  "$OPENOCD" -s "$SCRIPTS" -f interface/esp_usb_jtag.cfg -f target/esp32c3.cfg \
    -c "program_esp $file $offset verify exit" > "$WORK/program.log" 2>&1 || {
      cat "$WORK/program.log" >&2
      fail "OpenOCD program_esp failed at $file; full backup exists at $BACKUP"
    }
  grep -Eq 'Verified OK|Verif(y|ication).*OK|Verified' "$WORK/program.log" || {
    cat "$WORK/program.log" >&2
    fail "OpenOCD did not confirm verify for $file"
  }
done
echo "[4/5] Reset ESP32-C3 to boot written firmware"
"$OPENOCD" -s "$SCRIPTS" -f interface/esp_usb_jtag.cfg -f target/esp32c3.cfg \
  -c "init" -c "reset run" -c "shutdown" > "$WORK/reset.log" 2>&1 || {
    cat "$WORK/reset.log" >&2
    fail "Flash image verified, but reset failed"
  }
echo "[5/5] FLASH_DONE"
echo "SETUP_WIFI=ESP32C3-IR-Setup"
echo "SETUP_PASSWORD=esp32ir35"
echo "WEB_UI=http://192.168.4.1/"
echo "BACKUP=$BACKUP"

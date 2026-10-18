# Remote Mac flashing state (2026-10-18)

## Goal
Execute the pinned cloud-built ESP32-C3 IR-learning firmware on the user's Mac without Terminal copy/paste, and retrieve a structured execution receipt automatically.

## Implemented / committed
- Cloud build PASS, workflow run 39088472851, firmware artifact 12121886829, source e1accfdaaa7f01a85b714937d973c797e770e5b8.
- Local Mac flasher: scripts/flash_mac.command, pinned Git blob 719a72ee9070f105b3f386d43ec9af2c008ae620 (as of commit 0a9002897e62d7e18c42de347227817be177c580).
- Flash safeguards: automatic USB port discovery; ESP32-C3 chip verification; SHA256 verification; full original flash backup before write; fixed bootloader/partition/firmware image offsets; no erase-all.
- GitHub Issue bridge runner: mokumaisancho/GPT-Development-Suite/scripts/esp32_ir_flash_bridge.py, branch poc/native-local-bridge-v3, SHA-pinned flasher.
- New fixed Issue action ESP32_IR_FLASH added to scripts/github_issue_bridge_worker.py in commit a90ddb1be36d48e6a968fe9d17b77953957d943c.
- Only that approved firmware/flasher is eligible. No remotely chosen executable, argv, shell, paths, USB port or mutable firmware source.

## Remote attempts / truthful results
All commands submitted through https://github.com/mokumaisancho/GPT-Development-Suite/issues/11 .

| Command ID | Result |
|---|---|
| esp32-ir-bridge-status-20261018-1125 | ERROR: LOCAL_EXECUTION_ERROR:SuiteLoadError:SUITE_CHECKOUT_DIRTY |
| esp32-ir-sync-check-20261018-1126 | ERROR: SUITE_CHECKOUT_DIRTY |
| esp32-ir-sync-pinned-20261018-1140 | ERROR: SUITE_CHECKOUT_DIRTY |
| esp32-ir-self-bootstrap-20261018-1142 | ERROR: BOOTSTRAP_FAILED:1 after ~4.1s, receipt uploaded |
| esp32-ir-flash-once-20261018-1148 | ERROR: ACTION_NOT_ALLOWED (old Mac worker still loaded) |
| esp32-ir-ping-after-bootstrap-20261018-1151 | DONE: Mac Issue bridge online, reply and GitHub evidence uploaded |

## Current assessment
The GitHub-to-Mac Issue command transport and result-return path work. The new firmware-flash action has NOT been deployed to the running Mac process. The managed suite checkout fails the clean-tree guard, and the approved self-bootstrap did not repair it. No firmware write occurred through the remote job. The previous manual flash script also stopped before write because of checksum manifest path mismatch; the GitHub source fix is committed but not yet run on Mac.

## Remaining gate
Resolve actual tracked/untracked checkout changes under:

`$HOME/Library/Application Support/SUITEBrowserBridge/checkouts/GPT-Development-Suite-live`

without discarding user work; repair the installed Bootstrap; then perform `SYNC_PINNED` to commit a90ddb1be36d48e6a968fe9d17b77953957d943c and wait for daemon restart. Afterwards, dispatch a fresh unique-id `ESP32_IR_FLASH` (empty args) through Issue #11, and inspect the published result. Avoid repeating the prior rejected command ID; enforce single-run semantics to prevent reflashing on retries.

The USB device's current enumeration remains unverified after the user's earlier `/dev/cu.usbmodem101` not-found report.

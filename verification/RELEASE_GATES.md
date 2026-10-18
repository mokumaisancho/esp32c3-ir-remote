# ESP32-C3 IR release gates

Release state is **BLOCKED** unless each gate has an actual receipt for the exact same source SHA.
Do not equate code review or helper-only tests with hardware PASS.

| Gate | Mandatory evidence | Implementation | On failure |
|---|---|---|---|
| G0 source/impact | `scripts/check_impact.py`, `verification/impact_map.json` | CI first step | Block all subsequent steps |
| G1 regression | Python tests extracting the real receive implementation, FS / STA checks, native C++ sanitizer test | CI after G0 | Block build |
| G2 complete firmware | PlatformIO release-compatible ESP32-C3 build exit 0 | CI after G1 | Block artifact |
| G3 provenance | Firmware artifact manifest SHA256 and SOURCE_SHA equal triggering commit | CI artifact + Mac flash script | Block flash |
| G4 device rollback | Identify unique ESP32-C3, whole-flash backup with SHA256 | Mac flash script | Block flash |
| G5 program verification | ESP32-C3 firmware readback SHA256 matches downloaded artifact | Mac flash script | Never claim FLASH_DONE |
| G6 hardware E2E | Boot log; AP and STA `/api/status`; learn full window with real IR pulse; LittleFS save/reload; GPIO7 replay; Wi-Fi reconnect and mDNS | Real device; not yet automated | Do not claim E2E or close original issue |

## Change-impact policy

Any change to receive state transitions must revisit `tests/test_ir_wifi_integration.py` and its IDF HAL mocks, timeout expectations and error assertions. Filesystem and station retry changes require corresponding test contracts. Any changes to flash offsets, artifacts or verification must revisit `scripts/flash_mac.command` and CI artifact layout. Contracts are mapped in `impact_map.json`; `check_impact.py` fails CI if known implementation or test references disappear. This is not a substitute for test execution, firmware compilation, or genuine device validation.

Do not modify source and declare completion before G0-G5 run on the same commit. Never label G6 PASS without hardware evidence.

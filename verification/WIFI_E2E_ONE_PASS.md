# WiFiManager E2E single-pass execution contract

## Original goal
ESP32-C3 connects to the intended Wi-Fi network, obtains a usable IP address and serves the IR interface while remaining diagnosable without repeated user requests.

## Non-negotiable completion gates
1. CI compiles product firmware and tests without replacing real hardware evidence.
2. Artifact includes source SHA, FLASH_LAYOUT, bootloader, partition, boot_app0, application binary and SHA256SUMS; each item must hash-match.
3. Deliver artifact to the existing Google Drive path; confirm size and artifact->commit association.
4. When flashing is necessary, use the established Mac loader and full-flash backup/readback rather than publishing new named command files.
5. Start one bounded monitor on Mac after flash; capture serial messages including WIFI_TRACE/WIFI_DIAG_RESULT, USB enumerations, exceptions and elapsed time without asking the user to enable logs.
6. Every monitor run automatically saves dated local .log and machine-readable .json. User needs not manually enable diagnostic mode. Record observed events vs inference separately.
7. Auto-classify CONNECTED, AP_NOT_FOUND, AUTH_FAILED, HANDSHAKE_FAILED_OR_TIMEOUT, BEACON_TIMEOUT, ASSOCIATION_FAILED, SECURITY_PMKID_ERROR, IP_NOT_OBTAINED_OR_CONNECTION_LOST, DISCONNECTED_REASON_UNCLASSIFIED, CONNECTING_OR_PORTAL, and UNDETERMINED. No root cause beyond available evidence.
8. Probe Wi-FiManager setup portal (port 80), IR UI (port 8080) and /api/diagnostics, if reachable on the same network, without resetting USB serial. Validate HTTP success rather than equating Flash PASS with Wi-Fi PASS.
9. Stop with PASS only when STA_GOT_IP or live WiFi.status()==WL_CONNECTED AND reachable IR HTTP endpoint are observed. Otherwise BLOCKED with cause code and evidence; no invented success.
10. Document each test failure, its log, and one consolidated corrective change. Never repeat trial flashing merely to add obvious instrumentation.
11. No secret SSIDs, passwords, MAC addresses, tokens or Wi-Fi passwords in shared diagnostic receipts; avoid publishing local logs without explicit consent.

## Dependency order
CI/tests -> artifact/hashes -> Google Drive -> Mac backup/flash/readback -> auto monitor/logs/JSON -> Wi-Fi + HTTP check -> evidence-based RCA.

## Boundaries
Cloud cannot interact with the offline Mac via Drive alone. Mac must initiate the loader. Cloud CI success never proves STA association, DHCP or HTTP reachability. User action should be requested only for a physical action unavailable remotely, with a single complete instruction.

## Status at last update
- Product WiFiManager 2.0.17 integrated on branch fix/rmt-idf-error-diagnostics.
- Conservative firmware outcome classifier added.
- Auto-capture of firmware outcome plus periodic progress and JSON receipts implemented in scripts/wifi_trace_runner.py and copied to existing Google Doc loader source.
- Mac hardware classification and actual HTTP reachability not yet proven.

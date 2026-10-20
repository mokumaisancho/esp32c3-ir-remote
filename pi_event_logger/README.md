# ESP32-C3 → Raspberry Pi 5 alarm-event logging MVP

**State:** software implementation and localhost integration tests only. Physical
ESP32→Pi delivery is **NOT VERIFIED** until deployment and on-device evidence.
This repository contains a Pi safety stop for persistent undervoltage in the
home infrastructure records. Do not modify Pi services until that stop is
reviewed and the electrical cause is resolved.

## Transport and scope

- ESP32-C3 STA `192.168.2.141` → Pi wired LAN `192.168.2.131:5514/udp`.
- Fixed ~200-byte JSON per event. No SSH client, TLS, Google SDK, OAuth or
  24-hour event polling runs on ESP32. No raw IR pulses, credentials or SSIDs.
- `alarm_before_tx` immediately before invoking the RMT transmitter.
- `alarm_after_tx` reports driver result, frame count and time after send.
- `alarm_persist_failed` and `alarm_signal_missing` log action skips.
- Pi appends validated events to mode-0600 JSONL and calls `fsync()`.
  Log data never travels to an external cloud in this MVP.
- Receiver binds only the Pi's wired LAN IP, permits only the ESP STA IP and
  rejects non-schema packets. **An IP allowlist is not authentication.**
  This MVP must stay on a trusted private LAN; never forward UDP 5514.
  For an untrusted LAN or cloud uplink, add HMAC-SHA256/device credentials and
  Pi-side HTTPS/OAuth independently from ESP32.

## Sandbox PoC

```sh
python3 -m unittest discover -s pi_event_logger -p 'test_*.py' -v
```

Test covers actual UDP socket delivery on `127.0.0.1`, JSON validation,
file append/permissions and durable `fsync()`. It cannot verify local-LAN
routing, the Pi kernel, boot persistence or actual LED operation.

## Pi installation (do **not** run while power safety stop is active)

Requires only Python 3 stdlib. From a Pi checkout of this repository:

```sh
python3 -u pi_event_logger/receiver.py \
  --bind 192.168.2.131 --allow 192.168.2.141 --port 5514 \
  --dir "$HOME/.local/share/esp32-alarm-events"
```

Keep listener in foreground for initial PoC. It outputs `{"ready":true,...}`
and `{"accepted":true,"file":"..."}` upon successful storage. The
Pi's local JSONL files are the primary proof, not ESP32 UDP send success.
Validate next-day alarm `alarm_before_tx` / `alarm_after_tx` pair with
matching `boot`, `rule`, `slot`, and adjacent `seq` values.

## Deployment and safeguards

1. Re-check Pi undervoltage status and network IP; existing Pi files, router,
   Samba, Docker, WireGuard, SSH and USB shares are protected.
2. Confirm Pi receiver run under unprivileged `pi` account and that UDP/5514
   is not forwarded externally.
3. Verify direct Pi listener on LAN before flashing updated ESP firmware.
4. Build firmware in GitHub Actions and check app partition headroom.
5. Install only app partition on ESP32 with flash backup and readback.
6. Trigger one scheduled, noncritical IR action and verify **actual Pi
   JSONL** entry, Pi's NTP clock, and lamp response separately.
7. Record endpoint outage or missing event explicitly: this UDP MVP has
   no acknowledgement or offline spool, so it can lose records when Pi or
   Wi-Fi is unavailable. Do not classify unobserved events as successful.

## Route facts (2026-10-21)

The ChatGPT sandbox's interface is not connected to the user's private
`192.168.2.0/24` network. TCP probes to Pi ports 22, 8080 and 8081
returned `ECONNREFUSED`, **as did control probes to unrelated
external IPs**; they do not establish Pi being online/offline. Desktop
Commander reported the Mac device offline. Mac→Pi SSH previously worked
from the user's machine but is not a runnable sandbox bridge today.
No real Pi deployment or ESP32→Pi test has yet been performed.

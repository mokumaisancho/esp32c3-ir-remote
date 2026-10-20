# ESP32-C3 → Raspberry Pi 5 alarm-event logging MVP

**State:** software implementation and localhost integration tests only. Physical
ESP32→Pi delivery is **NOT VERIFIED** until deployment and on-device evidence.
This repository contains a Pi safety stop for persistent undervoltage in the
home infrastructure records. Do not modify Pi services until that stop is
reviewed and the electrical cause is resolved.

## Private, GPT-readable cloud log

Target: [Pi infrastructure private Issue #19](https://github.com/mokumaisancho/pi5-infrastructure-control/issues/19). The GitHub connector has successfully written and read back synthetic test comment `6303040555`. This proves GPT can retrieve private cloud events, **not** that the Pi hardware has delivered an event.

**Transport:** ESP32-C3 emits bounded pre/post UDP events to Pi `192.168.2.131:5514` → Pi validates and fsync-appends local JSONL → Pi's own background thread posts sanitized event data via outbound HTTPS to the PRIVATE GitHub issue → GPT reads private issue comments. No Mac, GAS, inbound SSH, router forwarding, or credentials on the ESP32. Raw IR pulses, IP addresses and Wi-Fi secrets are omitted from cloud comments.

### Pi start (only after Pi undervoltage/power-safety gate is cleared)

Run from a Pi checkout of this firmware repository as an unprivileged user:

```sh
# Set ESP32_ALARM_GITHUB_TOKEN via the Pi's existing private secret manager:
# fine-grained GitHub PAT scoped ONLY to private repo pi5-infrastructure-control;
# permission Issues read/write. Never commit or paste a token into ChatGPT.
python3 -u pi_event_logger/receiver.py \
  --bind 192.168.2.131 --allow 192.168.2.141 \
  --port 5514 --cloud \
  --dir "$HOME/.local/share/esp32-alarm-events"
```

If the dedicated token is absent, an existing authenticated `gh auth token` can be reused. If no token is available, `--cloud` stops rather than silently claiming delivery. ESP32 firmware retains no cloud secret.

The `ESP32_ALARM_EVENT_V1` comment contains a stable SHA-256 event ID, Pi receiver UTC, boot and sequence, alarm rule, saved signal slot, driver result, elapsed TX time and frames sent. GPT can retrieve and deduplicate by `event_id`. The local JSONL survives temporary Internet failures and is retried on Pi restart; a lost HTTP ACK can produce a duplicate cloud comment. **An ESP32 UDP datagram lost before Pi receives it cannot be recovered**, because the firmware has no ACK/retry queue.

The cloud uploader does not imply physical LED light output, and real Pi-to-GitHub transport still requires Pi-side deployment. CI tests run real localhost UDP and local fsync, plus mock HTTPS POST and crash/retry conditions. Avoid labeling those CI tests a Pi hardware pass.

## Transport and scope

- ESP32-C3 STA `192.168.2.141` → Pi wired LAN `192.168.2.131:5514/udp`.
- Fixed ~200-byte JSON per event. No SSH client, TLS, Google SDK, OAuth or
  24-hour event polling runs on ESP32. No raw IR pulses, credentials or SSIDs.
- `alarm_before_tx` immediately before invoking the RMT transmitter.
- `alarm_after_tx` reports driver result, frame count and time after send.
- `alarm_persist_failed` and `alarm_signal_missing` log action skips.
- Pi appends validated events to mode-0600 JSONL and calls `fsync()`.
  With --cloud, sanitized event metadata is delivered to private GitHub over Pi-side HTTPS.
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

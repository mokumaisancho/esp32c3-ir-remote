# ESP32-C3 IR Remote

ESP32-C3単体で動く、Wi-Fi経由の赤外線学習・送信リモコンです。

初期ターゲットは **ODELIC NRL-351N-JP**。元リモコン実機からRAWパルスを学習し、その内容をESP32-C3から再送信します。公開されているコード値を正本にはせず、手元の実機信号を正本にします。

## Hardware

- ESP32-C3
- Vishay TSOP38238
- IR Transmitter module

接続:

| Device | ESP32-C3 |
|---|---|
| TSOP38238 OUT | GPIO5 |
| TSOP38238 GND | GND |
| TSOP38238 VS | 3.3V |
| IR Transmitter DAT | GPIO7 |
| IR Transmitter GND | GND |
| IR Transmitter VCC | 3.3V |

## What the UI does

- 「5秒受信・記録」でGPIO5を最大5秒待機
- TSOP38238の復調済みRAW mark/spaceタイミングを取得
- 有効信号受信時は空きスロットに `capture-<slot>` として自動保存し、RAW（μs）と保存結果を返す（全32スロット使用中なら保存不可と明示）
- 任意の識別名を付けてLittleFSへ保存
- 保存済み信号を一覧表示
- 任意の保存信号をGPIO7から送信
- 直前に学習した信号を保存せずそのまま送信
- Wi-Fi設定をWeb UIから保存
- 同一LAN上から `http://esp32-ir.local/` でアクセス

初回またはWi-Fi接続失敗時は設定APを起動します。

- SSID: `ESP32C3-IR-Setup`
- Password: `esp32ir35`
- URL: `http://192.168.4.1/`

## NRL-351N-JP profile

送信の初期値:

- carrier: 38 kHz
- duty: 30%
- RX: GPIO5
- TX: GPIO7

NRL-351N-JPを実際に使った先行事例では38 kHz / 30%で受信・再送信して照明制御に成功しています。UI上の「全灯 / 消灯 / 常夜灯 / シーン」などは名前候補であり、固定コードを捏造しません。各ボタンは実機から学習して保存します。

Reference:
- https://qiita.com/hxbdy625/items/1eb79f261770182a84ea
- https://docs.espressif.com/projects/arduino-esp32/en/latest/api/rmt.html

## Build

PlatformIO / pioarduinoを使用します。Arduino-ESP32 3.3.11系に固定しています。

```bash
pio run
pio run -t upload
pio device monitor
```

UIはファームウェアへ埋め込まれているため、LittleFSイメージの別uploadは不要です。LittleFSは学習データ保存に使用します。

## Storage

最大32信号を保存します。

保存データは各スロットごとのバイナリで、以下を持ちます。

- user-defined name
- carrier frequency
- duty
- signed raw pulses (+mark / -space, microseconds)

同名保存は既存スロットを上書きします。

## Safety / scope

- HTTP UIは家庭内LAN向けで、インターネット公開を前提にしません。
- Flash書換えやOpenOCDは運用時には不要です。
- Mac/OpenOCD/GitHub Issue経路は開発・診断・復旧用として分離します。
- GPIO5/7のread-only実機診断経路は `mokumaisancho/esp-hardware-dev-console` と `mokumaisancho/GPT-Development-Suite` に証跡保存済みです。

## Current state

MVP source implemented:

- Wi-Fi STA + fallback setup AP
- mDNS
- embedded mobile Web UI
- 5-second RMT receive and automatic LittleFS RAW capture persistence
- RAW normalization
- LittleFS persistence
- saved signal list/delete
- immediate replay
- 38 kHz / 30% RMT transmit

Next gate is a real build/flash on the connected ESP32-C3, followed by NRL-351N-JP receive/replay E2E.

## 5-second hardware capture test (pending on-device firmware deployment)

The GPIO5 TSOP38238 output must be powered at 3.3 V and wired to the ESP32-C3 with a common GND. After the new firmware has been flashed and the setup AP or LAN HTTP UI is reachable, select **5秒受信・記録** and press any IR remote key while it is armed. The API returns `raw` as alternating signed microsecond durations (`+mark`, `-space`) and `stored`, `slot`, and `name`; a successful capture is saved to LittleFS automatically. Absence of a signal produces HTTP 408; full storage returns `stored=false` rather than a false positive. This is a DEMODULATED signal, not a sampled 38 kHz carrier waveform.

Real device receipt requires confirmation of firmware boot, positive pulse count, stored slot readback, and preferably a successful IR replay. Neither a static OpenOCD GPIO5=HIGH read nor a GitHub CI build is proof of physical IR reception. The existing GitHub Issue bridge transport is functional, but its live Mac worker has not accepted the new flash action due to checkout/deployment blockers. Avoid claiming this hardware test PASS before actual captured bytes and a GitHub receipt exist.

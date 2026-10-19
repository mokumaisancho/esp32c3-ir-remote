#include <Arduino.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <WebServer.h>
#include <WiFi.h>
#include <WiFiManager.h>
#include <esp32-hal-rmt.h>
#include <driver/rmt_rx.h>
#include <IRrecv.h>
#include <IRremoteESP8266.h>
#include <esp_err.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#include <algorithm>
#include <ctime>
#include <cstdlib>
#include <vector>

#include "alarm_policy.h"
#include "config.h"
#include "diagnostic_policy.h"
#include "web_ui_gzip.h"

namespace {

constexpr uint32_t SIGNAL_MAGIC = 0x31524945; // "EIR1"
constexpr uint16_t SIGNAL_VERSION = 1;
constexpr uint16_t SIGNAL_MULTI_VERSION = 2;
constexpr size_t MAX_EXTRA_FRAMES = 4;

struct Signal {
  String name;
  std::vector<int32_t> pulses; // +mark / -space, microseconds
  std::vector<std::vector<int32_t>> extraFrames;
  std::vector<uint32_t> interFrameGapUs;
  uint32_t carrierHz = ircfg::IR_CARRIER_HZ;
  uint16_t dutyPermille = 300;
};

// Port 80 belongs to WiFiManager captive portal; keep IR API on 8080.
WebServer server(8080);
WiFiManager wifiManager;
Signal lastSignal;
bool hasLastSignal = false;
alarm_policy::Rules alarmRules{};
bool alarmsReady = false;
bool ntpStarted = false;
bool ntpWasConnected = false;
String lastAlarmEvent = "未実行";

bool stationMode = false;
bool setupApReady = false;
bool fsReady = false;
bool mdnsReady = false;
bool wasStaConnected = false;
uint32_t staLastRetryMs = 0;
uint32_t staRetryCount = 0;
bool wifiCredentialsSaved = false;
bool wifiAttempted = false;
uint32_t wifiAttemptStartedMs = 0;
volatile int32_t wifiLastDisconnectReason = -1;
volatile uint32_t wifiDisconnectCount = 0;
volatile uint32_t wifiGotIpCount = 0;
volatile uint32_t wifiAssociationCount = 0;

// WiFi callbacks run in a different FreeRTOS task. Only atomic scalar writes,
// and serial logging, take place here; no WebServer/Preferences operations.
void onWifiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  const unsigned long ms = static_cast<unsigned long>(millis());
  switch (event) {
    case ARDUINO_EVENT_WIFI_STA_START:
      Serial.printf("WIFI_TRACE t=%lu event=STA_START\n", ms); break;
    case ARDUINO_EVENT_WIFI_STA_CONNECTED:
      ++wifiAssociationCount;
      Serial.printf("WIFI_TRACE t=%lu event=STA_CONNECTED association_count=%lu\n",
                    ms, static_cast<unsigned long>(wifiAssociationCount)); break;
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      wifiLastDisconnectReason = static_cast<int32_t>(info.wifi_sta_disconnected.reason);
      ++wifiDisconnectCount;
      Serial.printf("WIFI_TRACE t=%lu event=STA_DISCONNECTED reason=%ld count=%lu\n",
                    ms, static_cast<long>(wifiLastDisconnectReason),
                    static_cast<unsigned long>(wifiDisconnectCount)); break;
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      ++wifiGotIpCount;
      Serial.printf("WIFI_TRACE t=%lu event=STA_GOT_IP ip=" IPSTR
                    " gateway=" IPSTR " count=%lu\n",
                    ms, IP2STR(&info.got_ip.ip_info.ip),
                    IP2STR(&info.got_ip.ip_info.gw),
                    static_cast<unsigned long>(wifiGotIpCount)); break;
    case ARDUINO_EVENT_WIFI_STA_LOST_IP:
      Serial.printf("WIFI_TRACE t=%lu event=STA_LOST_IP\n", ms); break;
    case ARDUINO_EVENT_WIFI_AP_START:
      Serial.printf("WIFI_TRACE t=%lu event=AP_START\n", ms); break;
    case ARDUINO_EVENT_WIFI_AP_STOP:
      Serial.printf("WIFI_TRACE t=%lu event=AP_STOP\n", ms); break;
    default: break;
  }
}

bool rmtRxReady = false;
bool rmtTxReady = false;
rmt_channel_handle_t rxChannel = nullptr;
QueueHandle_t rxDoneQueue = nullptr;
// Activated only during the explicit library test; never shares GPIO5 with active RMT.
IRrecv comparisonReceiver(ircfg::IR_RX_PIN, 512, 25, false);
bool comparisonReceiverActive = false;
uint32_t libraryLastRawLength = 0;
bool libraryLastOverflow = false;
esp_err_t rxInitError = ESP_ERR_INVALID_STATE;
esp_err_t rxLastStartError = ESP_OK;
esp_err_t rxLastResetError = ESP_OK;
uint32_t rxLastSymbolCount = 0;
uint32_t rebootAt = 0;

rmt_data_t rxSymbols[ircfg::MAX_RMT_SYMBOLS];
rmt_data_t txSymbols[ircfg::MAX_RMT_SYMBOLS];

String signalPath(size_t slot) {
  char path[20];
  snprintf(path, sizeof(path), "/sig%02u.bin", static_cast<unsigned>(slot));
  return String(path);
}

String jsonEscape(const String &input) {
  String out;
  out.reserve(input.length() + 8);
  for (size_t i = 0; i < input.length(); ++i) {
    const uint8_t c = static_cast<uint8_t>(input[i]);
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[7];
          snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out;
}

void sendJson(int code, const String &payload) {
  server.sendHeader("Cache-Control", "no-store");
  server.send(code, "application/json; charset=utf-8", payload);
}

uint32_t signalDurationUs(const Signal &signal) {
  uint64_t total = 0;
  for (const int32_t pulse : signal.pulses) {
    total += static_cast<uint32_t>(pulse < 0 ? -static_cast<int64_t>(pulse) : pulse);
  }
  return static_cast<uint32_t>(std::min<uint64_t>(total, UINT32_MAX));
}

bool writeExact(File &file, const void *data, size_t size) {
  return file.write(reinterpret_cast<const uint8_t *>(data), size) == size;
}

bool readExact(File &file, void *data, size_t size) {
  return file.readBytes(reinterpret_cast<char *>(data), size) == size;
}

bool saveSignalToSlot(size_t slot, const Signal &signal) {
  if (slot >= ircfg::MAX_SIGNAL_SLOTS || signal.name.length() == 0 ||
      signal.name.length() > ircfg::MAX_NAME_BYTES ||
      signal.pulses.empty() || signal.pulses.size() > ircfg::MAX_PULSES) {
    return false;
  }

  if (!fsReady) return false;
  const String finalPath = signalPath(slot);
  const String tempPath = finalPath + ".tmp";
  LittleFS.remove(tempPath);

  File file = LittleFS.open(tempPath, "w");
  if (!file) return false;

  const uint32_t magic = SIGNAL_MAGIC;
  const uint16_t version = signal.extraFrames.empty() ? SIGNAL_VERSION : SIGNAL_MULTI_VERSION;
  const uint16_t nameLen = static_cast<uint16_t>(signal.name.length());
  const uint16_t pulseCount = static_cast<uint16_t>(signal.pulses.size());
  const uint32_t carrier = signal.carrierHz;
  const uint16_t duty = signal.dutyPermille;

  bool ok =
      writeExact(file, &magic, sizeof(magic)) &&
      writeExact(file, &version, sizeof(version)) &&
      writeExact(file, &nameLen, sizeof(nameLen)) &&
      writeExact(file, &pulseCount, sizeof(pulseCount)) &&
      writeExact(file, &carrier, sizeof(carrier)) &&
      writeExact(file, &duty, sizeof(duty)) &&
      writeExact(file, signal.name.c_str(), nameLen) &&
      writeExact(file, signal.pulses.data(), pulseCount * sizeof(int32_t));

  if (ok && version == SIGNAL_MULTI_VERSION) {
    const uint8_t extraCount = static_cast<uint8_t>(signal.extraFrames.size());
    ok = extraCount <= MAX_EXTRA_FRAMES &&
         signal.interFrameGapUs.size() == extraCount &&
         writeExact(file, &extraCount, sizeof(extraCount));
    for (size_t i = 0; ok && i < extraCount; ++i) {
      const auto &frame = signal.extraFrames[i];
      const uint16_t n = static_cast<uint16_t>(frame.size());
      ok = n >= 2 && n <= ircfg::MAX_PULSES &&
           writeExact(file, &signal.interFrameGapUs[i], sizeof(uint32_t)) &&
           writeExact(file, &n, sizeof(n)) &&
           writeExact(file, frame.data(), n * sizeof(int32_t));
    }
  }
  file.flush();
  file.close();

  if (!ok) {
    LittleFS.remove(tempPath);
    return false;
  }
  // Preserve the old slot if the new file cannot be installed.
  const String backupPath = finalPath + ".bak";
  LittleFS.remove(backupPath);
  const bool oldExists = LittleFS.exists(finalPath);
  if (oldExists && !LittleFS.rename(finalPath, backupPath)) {
    LittleFS.remove(tempPath);
    return false;
  }
  if (!LittleFS.rename(tempPath, finalPath)) {
    if (oldExists) LittleFS.rename(backupPath, finalPath);
    LittleFS.remove(tempPath);
    return false;
  }
  if (oldExists) LittleFS.remove(backupPath);
  return true;
}

bool loadSignalFromSlot(size_t slot, Signal &signal) {
  if (slot >= ircfg::MAX_SIGNAL_SLOTS) return false;
  if (!fsReady) return false;
  const String finalPath = signalPath(slot);
  const String backupPath = finalPath + ".bak";
  if (!LittleFS.exists(finalPath) && LittleFS.exists(backupPath))
    LittleFS.rename(backupPath, finalPath);
  File file = LittleFS.open(finalPath, "r");
  if (!file) return false;

  uint32_t magic = 0;
  uint16_t version = 0;
  uint16_t nameLen = 0;
  uint16_t pulseCount = 0;
  uint32_t carrier = 0;
  uint16_t duty = 0;

  bool ok =
      readExact(file, &magic, sizeof(magic)) &&
      readExact(file, &version, sizeof(version)) &&
      readExact(file, &nameLen, sizeof(nameLen)) &&
      readExact(file, &pulseCount, sizeof(pulseCount)) &&
      readExact(file, &carrier, sizeof(carrier)) &&
      readExact(file, &duty, sizeof(duty));

  if (!ok || magic != SIGNAL_MAGIC || (version != SIGNAL_VERSION && version != SIGNAL_MULTI_VERSION) ||
      nameLen == 0 || nameLen > ircfg::MAX_NAME_BYTES ||
      pulseCount == 0 || pulseCount > ircfg::MAX_PULSES ||
      carrier < 30000 || carrier > 60000 || duty < 100 || duty > 500) {
    file.close();
    return false;
  }

  String name;
  name.reserve(nameLen);
  for (uint16_t i = 0; i < nameLen; ++i) {
    const int c = file.read();
    if (c < 0) {
      file.close();
      return false;
    }
    name += static_cast<char>(c);
  }

  std::vector<int32_t> pulses(pulseCount);
  if (!readExact(file, pulses.data(), pulseCount * sizeof(int32_t))) {
    file.close();
    return false;
  }
  std::vector<std::vector<int32_t>> extraFrames;
  std::vector<uint32_t> gaps;
  if (version == SIGNAL_MULTI_VERSION) {
    uint8_t nFrames = 0;
    ok = readExact(file, &nFrames, sizeof(nFrames)) && nFrames <= MAX_EXTRA_FRAMES;
    for (uint8_t i = 0; ok && i < nFrames; ++i) {
      uint32_t gap = 0;
      uint16_t n = 0;
      ok = readExact(file, &gap, sizeof(gap)) && readExact(file, &n, sizeof(n)) &&
           n >= 2 && n <= ircfg::MAX_PULSES && gap <= 5000000U;
      if (!ok) break;
      std::vector<int32_t> frame(n);
      ok = readExact(file, frame.data(), n * sizeof(int32_t));
      if (ok) { gaps.push_back(gap); extraFrames.push_back(std::move(frame)); }
    }
  }
  file.close();
  if (!ok) return false;

  signal.name = name;
  signal.pulses = std::move(pulses);
  signal.extraFrames = std::move(extraFrames);
  signal.interFrameGapUs = std::move(gaps);
  signal.carrierHz = carrier;
  signal.dutyPermille = duty;
  return true;
}

int findSlotByName(const String &name) {
  for (size_t i = 0; i < ircfg::MAX_SIGNAL_SLOTS; ++i) {
    Signal signal;
    if (loadSignalFromSlot(i, signal) && signal.name == name) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

int findFreeSlot() {
  for (size_t i = 0; i < ircfg::MAX_SIGNAL_SLOTS; ++i) {
    if (!LittleFS.exists(signalPath(i))) return static_cast<int>(i);
  }
  return -1;
}

void appendPulse(std::vector<int32_t> &pulses, bool mark, uint32_t duration) {
  if (duration == 0) return;
  const int32_t signedDuration = mark ? static_cast<int32_t>(duration)
                                      : -static_cast<int32_t>(duration);
  if (!pulses.empty() && ((pulses.back() > 0) == (signedDuration > 0))) {
    const int64_t merged = static_cast<int64_t>(pulses.back()) + signedDuration;
    if (merged <= INT32_MAX && merged >= INT32_MIN) {
      pulses.back() = static_cast<int32_t>(merged);
      return;
    }
  }
  pulses.push_back(signedDuration);
}

Signal normalizeReceived(const rmt_data_t *symbols, size_t count) {
  Signal signal;
  signal.carrierHz = ircfg::IR_CARRIER_HZ;
  signal.dutyPermille = static_cast<uint16_t>(ircfg::IR_DUTY * 1000.0f);

  auto add = [&](uint16_t duration, uint8_t level) {
    if (!duration) return;
    const bool mark = ircfg::RX_ACTIVE_LOW ? (level == 0) : (level != 0);
    appendPulse(signal.pulses, mark, duration);
  };

  for (size_t i = 0; i < count; ++i) {
    add(symbols[i].duration0, symbols[i].level0);
    add(symbols[i].duration1, symbols[i].level1);
  }

  while (!signal.pulses.empty() && signal.pulses.front() < 0) {
    signal.pulses.erase(signal.pulses.begin());
  }
  while (!signal.pulses.empty() && signal.pulses.back() < 0) {
    signal.pulses.pop_back();
  }
  return signal;
}

// ESP-IDF RX exposes rmt_receive() failures that Arduino's rmtRead()
// wrapper does not report. A single in-flight receive is used per request.
static bool onRxDone(rmt_channel_handle_t channel,
                     const rmt_rx_done_event_data_t *event, void *context) {
  (void)channel;
  const size_t count = event->num_symbols;
  BaseType_t wake = pdFALSE;
  xQueueSendFromISR(static_cast<QueueHandle_t>(context), &count, &wake);
  return wake == pdTRUE;
}

bool learnSignal(Signal &signal, uint32_t &elapsedMs,
                 uint32_t &readAttempts, uint32_t &earlyFailures) {
  const uint32_t start = millis();
  elapsedMs = 0;
  readAttempts = 0;
  earlyFailures = 0;
  rxLastSymbolCount = 0;
  rxLastStartError = ESP_OK;
  rxLastResetError = ESP_OK;
  if (!rxChannel || !rxDoneQueue) return false;
  Serial.printf("IR_RX_BEGIN t=%lu multi=%d\n", static_cast<unsigned long>(start),
                server.hasArg("multi") && server.arg("multi") == "1" ? 1 : 0);

  const rmt_receive_config_t cfg = {
      .signal_range_min_ns = ircfg::RX_GLITCH_FILTER_US * 1000U,
      .signal_range_max_ns = ircfg::RX_IDLE_THRESHOLD_US * 1000U,
  };
  while (static_cast<uint32_t>(millis() - start) < ircfg::LEARN_WINDOW_MS) {
    xQueueReset(rxDoneQueue);
    ++readAttempts;
    rxLastStartError = rmt_receive(rxChannel, rxSymbols, sizeof(rxSymbols), &cfg);
    if (rxLastStartError != ESP_OK) {
      ++earlyFailures;
      elapsedMs = millis() - start;
      return false;
    }
    const uint32_t remaining = ircfg::LEARN_WINDOW_MS - (millis() - start);
    size_t count = 0;
    if (xQueueReceive(rxDoneQueue, &count, pdMS_TO_TICKS(remaining)) != pdTRUE) {
      Serial.printf("IR_RX_TIMEOUT attempts=%lu waited_ms=%lu symbols=%lu\n",
                    static_cast<unsigned long>(readAttempts),
                    static_cast<unsigned long>(millis() - start),
                    static_cast<unsigned long>(rxLastSymbolCount));
      rxLastResetError = rmt_disable(rxChannel);
      if (rxLastResetError == ESP_OK) rxLastResetError = rmt_enable(rxChannel);
      if (rxLastResetError != ESP_OK) rmtRxReady = false;
      break;
    }
    rxLastSymbolCount = static_cast<uint32_t>(count);
    if (count > 0 && count <= ircfg::MAX_RMT_SYMBOLS) {
      Signal candidate = normalizeReceived(rxSymbols, count);
      if (candidate.pulses.size() >= 6 && candidate.pulses.size() <= ircfg::MAX_PULSES) {
        signal = std::move(candidate);
        if (server.hasArg("multi") && server.arg("multi") == "1") {
          // Collect subsequent frames for up to 1.2 seconds after the first.
          // Short NEC repeat frames are valid even when they have under six pulses.
          const uint32_t multiUntil = millis() + 1200U;
          uint32_t prevEnd = millis();
          while (static_cast<int32_t>(multiUntil - millis()) > 0 &&
                 signal.extraFrames.size() < MAX_EXTRA_FRAMES) {
            xQueueReset(rxDoneQueue);
            const esp_err_t err = rmt_receive(rxChannel, rxSymbols, sizeof(rxSymbols), &cfg);
            if (err != ESP_OK) { Serial.printf("IR_MULTI_START_ERR=%d\n", static_cast<int>(err)); break; }
            const uint32_t remain = multiUntil - millis();
            size_t extraCount = 0;
            if (xQueueReceive(rxDoneQueue, &extraCount, pdMS_TO_TICKS(remain)) != pdTRUE) {
              rxLastResetError = rmt_disable(rxChannel);
              if (rxLastResetError == ESP_OK) rxLastResetError = rmt_enable(rxChannel);
              if (rxLastResetError != ESP_OK) rmtRxReady = false;
              break;
            }
            const uint32_t endMs = millis();
            if (extraCount == 0 || extraCount > ircfg::MAX_RMT_SYMBOLS) continue;
            Signal extra = normalizeReceived(rxSymbols, extraCount);
            if (extra.pulses.size() < 2 || extra.pulses.size() > ircfg::MAX_PULSES) continue;
            const uint32_t durationMs = (signalDurationUs(extra) + 999U) / 1000U;
            const uint32_t deltaMs = endMs - prevEnd;
            const uint32_t gapMs = deltaMs > durationMs ? deltaMs - durationMs : 0U;
            signal.interFrameGapUs.push_back(gapMs * 1000U);
            signal.extraFrames.push_back(std::move(extra.pulses));
            prevEnd = endMs;
          }
          Serial.printf("IR_MULTI_CAPTURE frames=%u\n",
                        static_cast<unsigned>(signal.extraFrames.size() + 1));
        }
        elapsedMs = millis() - start;
        return true;
      }
    }
    // A noise burst must not end the user-visible capture window.
    if (static_cast<uint32_t>(millis() - start) < ircfg::LEARN_WINDOW_MS) delay(1);
  }
  elapsedMs = millis() - start;
  return false;
}

bool learnWithLibrary(Signal &signal, uint32_t &elapsedMs) {
  const uint32_t started = millis();
  const bool wantMulti = server.hasArg("multi") && server.arg("multi") == "1";
  libraryLastRawLength = 0;
  libraryLastOverflow = false;
  rxLastStartError = ESP_OK;
  rxLastResetError = ESP_OK;
  rxLastSymbolCount = 0;
  if (!rxChannel) { rxLastStartError = ESP_ERR_INVALID_STATE; return false; }
  // Never activate GPIO-interrupt IRrecv while RMT owns the same input.
  const esp_err_t pauseResult = rmt_disable(rxChannel);
  if (pauseResult != ESP_OK) {
    rxLastResetError = pauseResult;
    return false;
  }
  comparisonReceiver.enableIRIn();
  comparisonReceiverActive = true;
  decode_results result;
  bool found = false;
  uint32_t multiDeadline = 0;
  while (millis() - started < ircfg::LEARN_WINDOW_MS ||
         (found && wantMulti && static_cast<int32_t>(multiDeadline - millis()) > 0)) {
    if (found && (!wantMulti || signal.extraFrames.size() >= MAX_EXTRA_FRAMES ||
                  static_cast<int32_t>(multiDeadline - millis()) <= 0)) break;
    if (!comparisonReceiver.decode(&result)) { delay(1); continue; }
    libraryLastRawLength = result.rawlen;
    libraryLastOverflow = result.overflow;
    const uint32_t gapUs = result.rawlen ?
        static_cast<uint32_t>(result.rawbuf[0]) * kRawTick : 0;
    Signal frame;
    frame.carrierHz = ircfg::IR_CARRIER_HZ;
    frame.dutyPermille = static_cast<uint16_t>(ircfg::IR_DUTY * 1000.0f);
    // rawbuf[0] is the gap before the frame; rawbuf[1] begins the IR mark.
    for (uint16_t i = 1; i < result.rawlen; ++i) {
      const uint32_t duration = static_cast<uint32_t>(result.rawbuf[i]) * kRawTick;
      if (duration != 0) appendPulse(frame.pulses, (i % 2) == 1, duration);
    }
    Serial.printf("IR_LIBRARY_FRAME rawlen=%u overflow=%d pulses=%u repeat=%d gap_us=%lu\n",
                  static_cast<unsigned>(result.rawlen), result.overflow ? 1 : 0,
                  static_cast<unsigned>(frame.pulses.size()), result.repeat ? 1 : 0,
                  static_cast<unsigned long>(gapUs));
    comparisonReceiver.resume();
    if (result.overflow || frame.pulses.size() < 2 ||
        frame.pulses.size() > ircfg::MAX_PULSES) continue;
    if (!found) {
      // An NEC short repeat alone cannot operate the lamp. Wait for a full first frame.
      if (frame.pulses.size() < 6) continue;
      signal = std::move(frame);
      found = true;
      if (!wantMulti) break;
      multiDeadline = millis() + 1200U;
    } else {
      signal.interFrameGapUs.push_back(gapUs);
      signal.extraFrames.push_back(std::move(frame.pulses));
    }
  }
  comparisonReceiver.disableIRIn();
  comparisonReceiverActive = false;
  rxLastResetError = rmt_enable(rxChannel);
  if (rxLastResetError != ESP_OK) rmtRxReady = false;
  elapsedMs = millis() - started;
  Serial.printf("IR_LIBRARY_END found=%d frames=%u rawlen=%lu overflow=%d elapsed_ms=%lu reset_err=%d\n",
                found ? 1 : 0, found ? static_cast<unsigned>(signal.extraFrames.size() + 1) : 0U,
                static_cast<unsigned long>(libraryLastRawLength),
                libraryLastOverflow ? 1 : 0, static_cast<unsigned long>(elapsedMs),
                static_cast<int>(rxLastResetError));
  return found && rxLastResetError == ESP_OK;
}

uint32_t lastTxDurationMs = 0;
uint32_t txAttemptCount = 0;
uint32_t lastTxFirstFrameMs = 0;
uint32_t lastTxGapMs = 0;
uint32_t lastTxFrameCount = 0;
bool transmitFrame(const Signal &signal, const std::vector<int32_t> &framePulses) {
  const uint32_t txBeginMs = millis();
  ++txAttemptCount;
  Serial.printf("IR_TX_START t=%lu attempt=%lu pulses=%u ready=%d carrier=%lu\n",
                static_cast<unsigned long>(millis()), static_cast<unsigned long>(txAttemptCount), static_cast<unsigned>(framePulses.size()),
                rmtTxReady ? 1 : 0, static_cast<unsigned long>(signal.carrierHz));
  if (!rmtTxReady || framePulses.empty()) {
    Serial.println("IR_TX_END result=FAIL reason=not_ready_or_empty");
    return false;
  }

  struct Segment {
    uint16_t duration;
    uint8_t level;
  };
  std::vector<Segment> segments;
  segments.reserve(framePulses.size());

  const uint8_t markLevel = ircfg::TX_ACTIVE_HIGH ? 1 : 0;
  const uint8_t spaceLevel = markLevel ? 0 : 1;

  for (const int32_t pulse : framePulses) {
    const bool mark = pulse > 0;
    uint32_t remaining = static_cast<uint32_t>(
        pulse < 0 ? -static_cast<int64_t>(pulse) : pulse);
    while (remaining) {
      const uint16_t chunk =
          static_cast<uint16_t>(std::min<uint32_t>(remaining, 32767));
      segments.push_back({chunk, mark ? markLevel : spaceLevel});
      remaining -= chunk;
      if (segments.size() > ircfg::MAX_PULSES) return false;
    }
  }

  const size_t symbolCount = (segments.size() + 1) / 2;
  if (symbolCount > ircfg::MAX_RMT_SYMBOLS) return false;

  for (size_t i = 0; i < symbolCount; ++i) {
    const Segment &a = segments[i * 2];
    txSymbols[i] = {};
    txSymbols[i].duration0 = a.duration;
    txSymbols[i].level0 = a.level;
    if (i * 2 + 1 < segments.size()) {
      const Segment &b = segments[i * 2 + 1];
      txSymbols[i].duration1 = b.duration;
      txSymbols[i].level1 = b.level;
    }
  }

  if (!rmtSetCarrier(
          ircfg::IR_TX_PIN,
          true,
          !ircfg::TX_ACTIVE_HIGH, // HAL maps this flag to polarity_active_low
          signal.carrierHz,
          signal.dutyPermille / 1000.0f)) {
    return false;
  }
  rmtSetEOT(ircfg::IR_TX_PIN, spaceLevel);
  // 120ms is sufficient for one normal IR frame (~65ms); avoid a full-second stall.
  const bool accepted = rmtWrite(ircfg::IR_TX_PIN, txSymbols, symbolCount, 200);
  lastTxDurationMs = millis() - txBeginMs;
  Serial.printf("IR_TX_END result=%s attempt=%lu symbols=%u gpio=%d duration_ms=%lu\n",
                accepted ? "DRIVER_OK" : "FAIL", static_cast<unsigned long>(txAttemptCount),
                static_cast<unsigned>(symbolCount), ircfg::IR_TX_PIN,
                static_cast<unsigned long>(lastTxDurationMs));
  return accepted;
}

bool transmitSignal(const Signal &signal, size_t maxFrames = MAX_EXTRA_FRAMES + 1) {
  const uint32_t startedMs = millis();
  lastTxFirstFrameMs = 0;
  lastTxGapMs = 0;
  lastTxFrameCount = 0;
  if (maxFrames == 0) return false;
  bool ok = transmitFrame(signal, signal.pulses);
  if (ok) {
    lastTxFrameCount = 1;
    lastTxFirstFrameMs = millis() - startedMs;
  }
  const size_t repeatCount = std::min(signal.extraFrames.size(), maxFrames - 1);
  for (size_t i = 0; ok && i < repeatCount; ++i) {
    if (i >= signal.interFrameGapUs.size()) { ok = false; break; }
    const uint32_t gapMs = std::min<uint32_t>((signal.interFrameGapUs[i] + 500U) / 1000U, 150U);
    const uint32_t gapStartMs = millis();
    delay(gapMs);
    lastTxGapMs += millis() - gapStartMs;
    Serial.printf("IR_TX_GAP frame=%u original_us=%lu applied_ms=%lu\n",
                  static_cast<unsigned>(i + 1),
                  static_cast<unsigned long>(signal.interFrameGapUs[i]),
                  static_cast<unsigned long>(gapMs));
    ok = transmitFrame(signal, signal.extraFrames[i]);
    if (ok) ++lastTxFrameCount;
  }
  lastTxDurationMs = millis() - startedMs;
  Serial.printf("IR_TX_SEQUENCE result=%s frames=%lu available_frames=%u first_frame_ms=%lu wait_ms=%lu duration_ms=%lu\n",
                ok ? "DRIVER_OK" : "FAIL",
                static_cast<unsigned long>(lastTxFrameCount),
                static_cast<unsigned>(signal.extraFrames.size() + 1),
                static_cast<unsigned long>(lastTxFirstFrameMs),
                static_cast<unsigned long>(lastTxGapMs),
                static_cast<unsigned long>(lastTxDurationMs));
  return ok;
}

String rawJson(const Signal &signal) {
  String json = "[";
  for (size_t i = 0; i < signal.pulses.size(); ++i) {
    if (i) json += ",";
    json += String(signal.pulses[i]);
  }
  json += "]";
  return json;
}

void handleStatus() {
  const bool staConnected = WiFi.status() == WL_CONNECTED;
  const IPAddress ip = staConnected ? WiFi.localIP() : WiFi.softAPIP();
  String json = "{";
  json += "\"ok\":true,";
  json += "\"profile\":\"" + jsonEscape(ircfg::PROFILE_NAME) + "\",";
  json += "\"network_mode\":\"" + String(staConnected ? "AP+STA" : "AP") + "\",";
  json += "\"ip\":\"" + ip.toString() + "\",";
  json += "\"sta_connected\":" + String(staConnected ? "true" : "false") + ",";
  json += "\"sta_status\":" + String(static_cast<int>(WiFi.status())) + ",";
  const bool wifiConnected = staConnected && WiFi.localIP() != IPAddress(0, 0, 0, 0);
  const char *wifiPhase = !wifiCredentialsSaved ? "UNCONFIGURED" :
      wifiConnected ? "CONNECTED" :
      !wifiAttempted ? "SAVED" :
      (millis() - wifiAttemptStartedMs < 12000U) ? "CONNECTING" : "FAILED";
  json += "\"wifi_phase\":\"" + String(wifiPhase) + "\",";
  json += "\"wifi_configured\":" + String(wifiCredentialsSaved ? "true" : "false") + ",";
  json += "\"wifi_attempt_elapsed_ms\":" + String(wifiAttempted ? (millis() - wifiAttemptStartedMs) : 0U) + ",";
  json += "\"sta_retry_count\":" + String(staRetryCount) + ",";
  json += "\"wifi_last_disconnect_reason\":" + String(static_cast<long>(wifiLastDisconnectReason)) + ",";
  json += "\"wifi_disconnect_count\":" + String(static_cast<unsigned long>(wifiDisconnectCount)) + ",";
  json += "\"wifi_association_count\":" + String(static_cast<unsigned long>(wifiAssociationCount)) + ",";
  json += "\"wifi_got_ip_count\":" + String(static_cast<unsigned long>(wifiGotIpCount)) + ",";
  json += "\"mdns_ready\":" + String(mdnsReady ? "true" : "false") + ",";
  json += "\"sta_ssid\":\"" + jsonEscape(staConnected ? WiFi.SSID() : String("")) + "\",";
  json += "\"sta_ip\":\"" + (staConnected ? WiFi.localIP().toString() : String("")) + "\",";
  json += "\"setup_ap_ready\":" + String(setupApReady ? "true" : "false") + ",";
  json += "\"setup_ap_ssid\":\"" + String(ircfg::SETUP_AP_SSID) + "\",";
  json += "\"setup_ap_ip\":\"" + (setupApReady ? WiFi.softAPIP().toString() : String("")) + "\",";
  json += "\"hostname\":\"" + String(ircfg::MDNS_HOST) + ".local\",";
  json += "\"rx_gpio\":" + String(ircfg::IR_RX_PIN) + ",";
  json += "\"tx_gpio\":" + String(ircfg::IR_TX_PIN) + ",";
  json += "\"rmt_rx_ready\":" + String(rmtRxReady ? "true" : "false") + ",";
  json += "\"filesystem_ready\":" + String(fsReady ? "true" : "false") + ",";
  json += "\"rmt_tx_ready\":" + String(rmtTxReady ? "true" : "false") + ",";
  json += "\"carrier_hz\":" + String(ircfg::IR_CARRIER_HZ) + ",";
  json += "\"duty\":" + String(ircfg::IR_DUTY, 2) + ",";
  json += "\"has_last\":" + String(hasLastSignal ? "true" : "false");
  json += "}";
  sendJson(200, json);
}

void handleLearn() {
  if (!rmtRxReady) {
    sendJson(503, String("{\"ok\":false,\"reason\":\"rmt_not_ready\",\"init_esp_err\":") +
                  String(static_cast<int>(rxInitError)) + "}");
    return;
  }

  Signal captured;
  uint32_t elapsedMs = 0;
  uint32_t readAttempts = 0;
  uint32_t earlyFailures = 0;
  const bool libraryMode = server.hasArg("backend") && server.arg("backend") == "library";
  const bool received = libraryMode ? learnWithLibrary(captured, elapsedMs) :
      learnSignal(captured, elapsedMs, readAttempts, earlyFailures);
  if (!received) {
    const bool startFailed = rxLastStartError != ESP_OK;
    const bool resetFailed = rxLastResetError != ESP_OK;
    const char *reason = irpolicy::rxFailureReason(startFailed, resetFailed,
                                                   rxLastSymbolCount);
    String json = "{\"ok\":false,\"reason\":\"" + String(reason) + "\"";
    json += ",\"elapsed_ms\":" + String(elapsedMs);
    json += ",\"start_esp_err\":" + String(static_cast<int>(rxLastStartError));
    json += ",\"reset_esp_err\":" + String(static_cast<int>(rxLastResetError));
    json += ",\"symbol_count\":" + String(rxLastSymbolCount);
    json += ",\"read_attempts\":" + String(readAttempts);
    json += ",\"early_failures\":" + String(earlyFailures);
    json += ",\"backend\":\"" + String(libraryMode ? "library" : "rmt") + "\"";
    json += ",\"raw_length\":" + String(libraryMode ? libraryLastRawLength : rxLastSymbolCount);
    json += ",\"overflow\":" + String(libraryMode && libraryLastOverflow ? "true" : "false") + "}";
    sendJson(startFailed || resetFailed ? 503 : 408, json);
    return;
  }

  lastSignal = std::move(captured);
  hasLastSignal = true;

  const int slot = findFreeSlot();
  bool stored = false;
  String autoName;
  if (slot >= 0) {
    autoName = "capture-" + String(slot);
    Signal persistent = lastSignal;
    persistent.name = autoName;
    stored = saveSignalToSlot(static_cast<size_t>(slot), persistent);
  }

  String json = "{";
  json += "\"ok\":true,";
  json += "\"backend\":\"" + String(libraryMode ? "library" : "rmt") + "\",";
  json += "\"stored\":" + String(stored ? "true" : "false") + ",";
  json += "\"slot\":" + String(stored ? slot : -1) + ",";
  json += "\"name\":\"" + jsonEscape(stored ? autoName : String("")) + "\",";
  json += "\"pulses\":" + String(lastSignal.pulses.size()) + ",";
  json += "\"duration_us\":" + String(signalDurationUs(lastSignal)) + ",";
  json += "\"frames\":" + String(lastSignal.extraFrames.size() + 1) + ",";
  json += "\"elapsed_ms\":" + String(elapsedMs) + ",";
  json += "\"raw\":" + rawJson(lastSignal);
  json += "}";
  sendJson(200, json);
}

void handleSave() {
  if (!hasLastSignal) {
    sendJson(409, "{\"ok\":false,\"error\":\"保存できる受信信号がありません\"}");
    return;
  }
  String name = server.arg("name");
  name.trim();
  if (name.length() == 0 || name.length() > ircfg::MAX_NAME_BYTES) {
    sendJson(400, "{\"ok\":false,\"error\":\"識別名が空、または長すぎます\"}");
    return;
  }

  int slot = findSlotByName(name);
  if (slot < 0) slot = findFreeSlot();
  if (slot < 0) {
    sendJson(507, "{\"ok\":false,\"error\":\"保存スロットが満杯です\"}");
    return;
  }

  Signal toSave = lastSignal;
  toSave.name = name;
  if (!saveSignalToSlot(static_cast<size_t>(slot), toSave)) {
    sendJson(500, "{\"ok\":false,\"error\":\"LittleFSへの保存に失敗しました\"}");
    return;
  }
  sendJson(200, "{\"ok\":true,\"id\":" + String(slot) + "}");
}

void handleSignals() {
  String json = "[";
  bool first = true;
  for (size_t i = 0; i < ircfg::MAX_SIGNAL_SLOTS; ++i) {
    Signal signal;
    if (!loadSignalFromSlot(i, signal)) continue;
    if (!first) json += ",";
    first = false;
    json += "{";
    json += "\"id\":" + String(i) + ",";
    json += "\"name\":\"" + jsonEscape(signal.name) + "\",";
    json += "\"pulses\":" + String(signal.pulses.size()) + ",";
    json += "\"frames\":" + String(signal.extraFrames.size() + 1) + ",";
    json += "\"duration_us\":" + String(signalDurationUs(signal));
    json += "}";
  }
  json += "]";
  sendJson(200, json);
}

bool parseSlot(int &slot) {
  if (!server.hasArg("id")) return false;
  const String raw = server.arg("id");
  for (size_t i = 0; i < raw.length(); ++i) {
    if (!isDigit(raw[i])) return false;
  }
  slot = raw.toInt();
  return slot >= 0 && slot < static_cast<int>(ircfg::MAX_SIGNAL_SLOTS);
}

String transmissionResult(uint32_t loadMs, uint32_t totalMs) {
  return String("{\"ok\":true,\"result\":\"DRIVER_OK\",\"verified_by_receiver\":false,\"tx_duration_ms\":") +
         String(lastTxDurationMs) + ",\"tx_first_frame_ms\":" + String(lastTxFirstFrameMs) +
         ",\"tx_gap_wait_ms\":" + String(lastTxGapMs) +
         ",\"tx_frames_sent\":" + String(lastTxFrameCount) +
         ",\"load_ms\":" + String(loadMs) +
         ",\"handler_ms\":" + String(totalMs) +
         ",\"tx_attempt\":" + String(txAttemptCount) + "}";
}

size_t requestedFrames() {
  if (!server.hasArg("max_frames") || server.arg("max_frames") == "0") {
    return MAX_EXTRA_FRAMES + 1;
  }
  if (server.arg("max_frames") == "1") return 1;
  return 0; // Invalid options must not be silently accepted.
}

void handleSendSaved() {
  const uint32_t requestMs = millis();
  int slot = -1;
  if (!parseSlot(slot)) {
    sendJson(400, "{\"ok\":false,\"error\":\"idが不正です\"}");
    return;
  }
  const size_t maxFrames = requestedFrames();
  if (maxFrames == 0) {
    sendJson(400, "{\"ok\":false,\"error\":\"max_framesが不正です\"}");
    return;
  }
  Signal signal;
  if (!loadSignalFromSlot(slot, signal)) {
    sendJson(404, "{\"ok\":false,\"error\":\"信号が見つかりません\"}");
    return;
  }
  const uint32_t loadMs = millis() - requestMs;
  if (!transmitSignal(signal, maxFrames)) {
    sendJson(500, "{\"ok\":false,\"error\":\"IR送信に失敗しました\"}");
    return;
  }
  sendJson(200, transmissionResult(loadMs, millis() - requestMs));
}

void handleSendLast() {
  const uint32_t requestMs = millis();
  if (!hasLastSignal) {
    sendJson(409, "{\"ok\":false,\"error\":\"送信できる直近信号がありません\"}");
    return;
  }
  const size_t maxFrames = requestedFrames();
  if (maxFrames == 0) {
    sendJson(400, "{\"ok\":false,\"error\":\"max_framesが不正です\"}");
    return;
  }
  if (!transmitSignal(lastSignal, maxFrames)) {
    sendJson(500, "{\"ok\":false,\"error\":\"IR送信に失敗しました\"}");
    return;
  }
  sendJson(200, transmissionResult(0, millis() - requestMs));
}

void handleDelete() {
  int slot = -1;
  if (!parseSlot(slot)) {
    sendJson(400, "{\"ok\":false,\"error\":\"idが不正です\"}");
    return;
  }
  for (const auto &rule : alarmRules) {
    if (rule.days && rule.slot == static_cast<uint8_t>(slot)) {
      sendJson(409, "{\"ok\":false,\"error\":\"照明アラームが参照中です。先にアラームを削除してください\"}");
      return;
    }
  }
  if (!LittleFS.exists(signalPath(slot))) {
    sendJson(404, "{\"ok\":false,\"error\":\"信号が見つかりません\"}");
    return;
  }
  if (!LittleFS.remove(signalPath(slot))) {
    sendJson(500, "{\"ok\":false,\"error\":\"削除に失敗しました\"}");
    return;
  }
  sendJson(200, "{\"ok\":true}");
}

void diagMark(const char *phase);
void handleDiagnostics();
void handleWifi() {
  String ssid = server.arg("ssid");
  String password = server.arg("password");
  ssid.trim();
  if (ssid.length() == 0 || ssid.length() > 32 || password.length() > 63) {
    sendJson(400, "{\"ok\":false,\"error\":\"SSIDまたはパスワードが不正です\"}");
    return;
  }

  Preferences prefs;
  if (!prefs.begin("irwifi", false)) {
    sendJson(500, "{\"ok\":false,\"error\":\"Wi-Fi設定保存を開始できません\"}");
    return;
  }
  // Empty passphrases are valid for an open network; verify round-trip.
  const bool wroteSsid = prefs.putString("ssid", ssid) == ssid.length();
  const bool wrotePass = prefs.putString("pass", password) == password.length();
  const bool ok = wroteSsid && wrotePass &&
      prefs.getString("ssid", "") == ssid &&
      prefs.getString("pass", "") == password;
  prefs.end();

  if (!ok) {
    sendJson(500, "{\"ok\":false,\"error\":\"Wi-Fi設定保存に失敗しました\"}");
    return;
  }
  wifiCredentialsSaved = true;
  wifiAttempted = true;
  wifiAttemptStartedMs = millis();
  // Begin STA connection immediately; keep AP and Web UI operational.
  Serial.printf("WIFI_TRACE t=%lu event=CONFIG_UPDATE ssid_len=%u pass_len=%u\n",
                static_cast<unsigned long>(millis()),
                static_cast<unsigned>(ssid.length()),
                static_cast<unsigned>(password.length()));
  // Legacy IR form retained; WiFiManager portal is the supported setup path.
  WiFi.begin(ssid.c_str(), password.c_str());
  diagMark("CONFIG_STA_BEGIN_CALLED");
  staLastRetryMs = millis();
  sendJson(202, "{\"ok\":true,\"saved\":true,\"connected\":false,\"wifi_phase\":\"CONNECTING\"}");
}

// Lighting alarms: local wall-clock JST (UTC+9, no DST).
// Existing /sigNN.bin IR files are not modified by this feature.

constexpr char kAlarmsPath[] = "/alarms.bin";
constexpr char kAlarmsBackupPath[] = "/alarms.bak";
constexpr char kAlarmsTempPath[] = "/alarms.tmp";

bool loadAlarmRules() {
  if (!fsReady) return false;
  if (!LittleFS.exists(kAlarmsPath) && LittleFS.exists(kAlarmsBackupPath)) {
    if (!LittleFS.rename(kAlarmsBackupPath, kAlarmsPath)) return false;
  }
  if (!LittleFS.exists(kAlarmsPath)) {
    alarmRules = {};
    return true; // Fresh installation: no rules yet.
  }
  File f = LittleFS.open(kAlarmsPath, "r");
  if (!f) return false;
  alarm_policy::Bytes bytes{};
  const bool sizeOk = f.size() == bytes.size();
  const bool readOk = sizeOk && f.read(bytes.data(), bytes.size()) == bytes.size();
  f.close();
  return readOk && alarm_policy::decode(bytes.data(), bytes.size(), alarmRules);
}

bool persistAlarmRules() {
  if (!fsReady || !alarmsReady) return false;
  const auto bytes = alarm_policy::encode(alarmRules);
  LittleFS.remove(kAlarmsTempPath);
  File f = LittleFS.open(kAlarmsTempPath, "w");
  if (!f) return false;
  const bool written = f.write(bytes.data(), bytes.size()) == bytes.size();
  f.flush();
  f.close();
  if (!written) { LittleFS.remove(kAlarmsTempPath); return false; }
  // Preserve the previous valid schedule if a replacement fails.
  LittleFS.remove(kAlarmsBackupPath);
  const bool oldExists = LittleFS.exists(kAlarmsPath);
  if (oldExists && !LittleFS.rename(kAlarmsPath, kAlarmsBackupPath)) {
    LittleFS.remove(kAlarmsTempPath);
    return false;
  }
  if (!LittleFS.rename(kAlarmsTempPath, kAlarmsPath)) {
    if (oldExists) LittleFS.rename(kAlarmsBackupPath, kAlarmsPath);
    LittleFS.remove(kAlarmsTempPath);
    return false;
  }
  if (oldExists) LittleFS.remove(kAlarmsBackupPath);
  return true;
}

bool safeUnsigned(const String &value, uint32_t max, uint32_t &out) {
  if (value.isEmpty() || value.length() > 10) return false;
  uint32_t candidate = 0;
  for (size_t i = 0; i < value.length(); ++i) {
    if (!isDigit(value[i])) return false;
    const uint32_t d = static_cast<uint32_t>(value[i] - '0');
    if (candidate > (max - d) / 10U || d > max) return false;
    candidate = candidate * 10U + d;
  }
  out = candidate;
  return true;
}

bool alarmClockValid() {
  return ntpStarted && WiFi.status() == WL_CONNECTED &&
         time(nullptr) >= static_cast<time_t>(1760000000);
}

void handleGetAlarms() {
  const bool clockOk = alarmClockValid();
  String result = "{\"ok\":true,\"storage_ready\":";
  result += alarmsReady ? "true" : "false";
  result += ",\"clock_valid\":";
  result += clockOk ? "true" : "false";
  result += ",\"timezone\":\"JST (UTC+09:00)\",\"clock\":\"";
  if (clockOk) {
    const time_t now = time(nullptr);
    struct tm local{};
    localtime_r(&now, &local);
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &local);
    result += stamp;
  } else {
    result += "NTP時刻同期待ち";
  }
  result += "\",\"last_event\":\"" + jsonEscape(lastAlarmEvent) + "\",\"rules\":[";
  bool first = true;
  for (size_t i = 0; i < alarmRules.size(); ++i) {
    const auto &r = alarmRules[i];
    if (!r.days) continue;
    if (!first) result += ",";
    first = false;
    result += "{\"id\":" + String(i) +
              ",\"days\":" + String(r.days) +
              ",\"hour\":" + String(r.hour) +
              ",\"minute\":" + String(r.minute) +
              ",\"slot\":" + String(r.slot) +
              ",\"enabled\":" + String(r.enabled ? "true" : "false") +
              ",\"first_only\":" + String(r.firstOnly ? "true" : "false") +
              "}";
  }
  result += "]}";
  sendJson(200, result);
}

void handleSaveAlarm() {
  if (!alarmsReady) {
    sendJson(503, "{\"ok\":false,\"error\":\"アラーム保存領域を利用できません\"}");
    return;
  }
  uint32_t days=0, hour=0, minute=0, slot=0, enabled=0, firstOnly=0, id=0;
  if (!safeUnsigned(server.arg("days"), 127, days) || days == 0 ||
      !safeUnsigned(server.arg("hour"), 23, hour) ||
      !safeUnsigned(server.arg("minute"), 59, minute) ||
      !safeUnsigned(server.arg("slot"), ircfg::MAX_SIGNAL_SLOTS - 1, slot) ||
      !safeUnsigned(server.arg("enabled"), 1, enabled) ||
      !safeUnsigned(server.arg("first_only"), 1, firstOnly)) {
    sendJson(400, "{\"ok\":false,\"error\":\"曜日・時刻・信号の設定が不正です\"}");
    return;
  }
  Signal verifySignal;
  if (!loadSignalFromSlot(slot, verifySignal)) {
    sendJson(400, "{\"ok\":false,\"error\":\"保存済み赤外線信号が見つかりません\"}");
    return;
  }
  size_t index = alarmRules.size();
  if (server.hasArg("id")) {
    if (!safeUnsigned(server.arg("id"), alarmRules.size() - 1, id) ||
        !alarmRules[id].days) {
      sendJson(400, "{\"ok\":false,\"error\":\"更新対象IDが不正です\"}");
      return;
    }
    index = id;
  } else {
    for (size_t i = 0; i < alarmRules.size(); ++i) {
      if (!alarmRules[i].days) { index = i; break; }
    }
  }
  if (index >= alarmRules.size()) {
    sendJson(507, "{\"ok\":false,\"error\":\"アラームは16件までです\"}");
    return;
  }
  const alarm_policy::Rules before = alarmRules;
  auto &r = alarmRules[index];
  r.days = days; r.hour = hour; r.minute = minute;
  r.slot = slot; r.enabled = enabled; r.firstOnly = firstOnly;
  // Saving a rule during a matching minute must not immediately turn on lights.
  r.lastMinute = alarmClockValid() ? static_cast<uint32_t>(time(nullptr) / 60) : 0;
  if (!persistAlarmRules()) {
    alarmRules = before;
    sendJson(500, "{\"ok\":false,\"error\":\"アラーム保存に失敗しました\"}");
    return;
  }
  sendJson(200, "{\"ok\":true,\"id\":" + String(index) + "}");
}

void handleDeleteAlarm() {
  uint32_t id = 0;
  if (!alarmsReady || !safeUnsigned(server.arg("id"), alarmRules.size()-1, id) ||
      !alarmRules[id].days) {
    sendJson(400, "{\"ok\":false,\"error\":\"削除対象のアラームがありません\"}");
    return;
  }
  const alarm_policy::Rules before = alarmRules;
  alarmRules[id] = {};
  if (!persistAlarmRules()) {
    alarmRules = before;
    sendJson(500, "{\"ok\":false,\"error\":\"アラーム削除に失敗しました\"}");
    return;
  }
  sendJson(200, "{\"ok\":true}");
}

void runAlarmClock() {
  // Clock synchronization runs in the main loop, not in a Wi-Fi callback.
  // Never block an IR button press with an NTP synchronization wait.
  const bool connected = WiFi.status() == WL_CONNECTED;
  if (connected && !ntpWasConnected) {
    configTzTime("JST-9", "ntp.nict.jp", "pool.ntp.org", "time.google.com");
    ntpStarted = true;
    Serial.println("ALARM_NTP_STARTED");
  }
  ntpWasConnected = connected;
  if (!connected || !alarmsReady || !alarmClockValid()) return;
  static uint32_t lastCheckMs = 0;
  const uint32_t nowMs = millis();
  if (nowMs - lastCheckMs < 1000U) return;
  lastCheckMs = nowMs;
  const time_t now = time(nullptr);
  struct tm local{};
  if (!localtime_r(&now, &local)) return;
  const uint32_t epochMinute = static_cast<uint32_t>(now / 60);
  for (size_t i = 0; i < alarmRules.size(); ++i) {
    auto &r = alarmRules[i];
    if (!alarm_policy::due(r, local.tm_wday, local.tm_hour, local.tm_min, epochMinute))
      continue;
    // Persist deduplication before sending. Do not risk repeated alarms after reboot.
    const uint32_t previous = r.lastMinute;
    r.lastMinute = epochMinute;
    if (!persistAlarmRules()) {
      r.lastMinute = previous;
      lastAlarmEvent = "保存エラー：自動送信を中止";
      Serial.printf("ALARM_SKIP id=%u reason=persist_failed\n", static_cast<unsigned>(i));
      continue;
    }
    Signal stored;
    if (!loadSignalFromSlot(r.slot, stored)) {
      lastAlarmEvent = "信号が見つかりません #" + String(r.slot);
      Serial.printf("ALARM_SKIP id=%u reason=signal_missing\n", static_cast<unsigned>(i));
      continue;
    }
    const bool ok = transmitSignal(stored, r.firstOnly ? 1 : MAX_EXTRA_FRAMES + 1);
    lastAlarmEvent = String("ルール#") + String(i) + " " + String(ok ? "送信処理OK" : "送信失敗") +
                     " / 信号#" + String(r.slot) + " / " + String(local.tm_hour) +
                     ":" + String(local.tm_min);
    Serial.printf("ALARM_TRIGGER id=%u slot=%u weekday=%d time=%02d:%02d result=%s\n",
                  static_cast<unsigned>(i), static_cast<unsigned>(r.slot),
                  local.tm_wday, local.tm_hour, local.tm_min, ok ? "DRIVER_OK" : "FAIL");
  }
}

void setupRoutes() {
  server.on("/", HTTP_GET, []() {
    server.sendHeader("Cache-Control", "no-store");
    server.sendHeader("Content-Encoding", "gzip");
    server.send_P(200, "text/html; charset=utf-8",
                  reinterpret_cast<PGM_P>(INDEX_HTML_GZ), INDEX_HTML_GZ_LEN);
  });
  server.on("/api/status", HTTP_GET, handleStatus);
  server.on("/api/diagnostics", HTTP_GET, handleDiagnostics);
  server.on("/api/learn", HTTP_POST, handleLearn);
  server.on("/api/save", HTTP_POST, handleSave);
  server.on("/api/signals", HTTP_GET, handleSignals);
  server.on("/api/send", HTTP_POST, handleSendSaved);
  server.on("/api/send-last", HTTP_POST, handleSendLast);
  server.on("/api/delete", HTTP_POST, handleDelete);
  server.on("/api/wifi", HTTP_POST, handleWifi);
  server.on("/api/alarms", HTTP_GET, handleGetAlarms);
  server.on("/api/alarms/save", HTTP_POST, handleSaveAlarm);
  server.on("/api/alarms/delete", HTTP_POST, handleDeleteAlarm);
  server.onNotFound([]() {
    sendJson(404, "{\"ok\":false,\"error\":\"not found\"}");
  });
}

// Read-only, bounded boot flight recorder. No passwords or SSIDs stored.
constexpr size_t kDiagSlots = 32;
String diagSteps[kDiagSlots];
uint32_t diagTimes[kDiagSlots] = {};
size_t diagCount = 0;
void diagMark(const char *phase) {
  const size_t index = diagCount % kDiagSlots;
  diagSteps[index] = phase;
  diagTimes[index] = millis();
  ++diagCount;
  Serial.printf("WIFI_DIAG t=%lu step=%s\n", static_cast<unsigned long>(millis()), phase);
}
// Conservative evidence-based classification; do not infer router-side root cause.
const char* wifiOutcome() {
  if (WiFi.status() == WL_CONNECTED) return "CONNECTED";
  const int32_t reason = wifiLastDisconnectReason;
  switch (reason) {
    case 201: return "AP_NOT_FOUND";
    case 202: return "AUTH_FAILED";
    case 15: case 204: return "HANDSHAKE_FAILED_OR_TIMEOUT";
    case 200: return "BEACON_TIMEOUT";
    case 203: return "ASSOCIATION_FAILED";
    case 205: return "CONNECTION_FAILED_UNSPECIFIED";
    case 206: return "SECURITY_PMKID_ERROR";
    default: break;
  }
  if (wifiAssociationCount > wifiGotIpCount &&
      static_cast<uint32_t>(millis() - wifiAttemptStartedMs) >= 30000U)
    return "IP_NOT_OBTAINED_OR_CONNECTION_LOST";
  if (wifiDisconnectCount > 0) return "DISCONNECTED_REASON_UNCLASSIFIED";
  if (!wifiCredentialsSaved) return "CREDENTIALS_NOT_CONFIRMED";
  if (wifiAttempted) return "CONNECTING_OR_PORTAL";
  return "NOT_STARTED";
}
void handleDiagnostics() {
  String json = "{\"ok\":true,\"uptime_ms\":" + String(millis());
  json += ",\"wifi_status\":" + String(static_cast<int>(WiFi.status()));
  json += ",\"configured\":" + String(wifiCredentialsSaved ? "true" : "false");
  json += ",\"ap_ready\":" + String(setupApReady ? "true" : "false");
  json += ",\"sta_connected\":" + String(WiFi.status() == WL_CONNECTED ? "true" : "false");
  json += ",\"sta_ip\":\"" + WiFi.localIP().toString() + "\"";
  json += ",\"last_disconnect_reason\":" + String(static_cast<long>(wifiLastDisconnectReason));
  json += ",\"outcome\":\"" + String(wifiOutcome()) + "\"";
  json += ",\"disconnect_count\":" + String(static_cast<unsigned long>(wifiDisconnectCount));
  json += ",\"association_count\":" + String(static_cast<unsigned long>(wifiAssociationCount));
  json += ",\"got_ip_count\":" + String(static_cast<unsigned long>(wifiGotIpCount));
  json += ",\"retry_count\":" + String(static_cast<unsigned long>(staRetryCount));
  json += ",\"events\":[";
  const size_t n = diagCount < kDiagSlots ? diagCount : kDiagSlots;
  const size_t first = diagCount > kDiagSlots ? diagCount - kDiagSlots : 0;
  for (size_t i = 0; i < n; ++i) {
    const size_t slot = (first + i) % kDiagSlots;
    if (i) json += ",";
    json += "{\"ms\":" + String(diagTimes[slot]) + ",\"step\":\"" + diagSteps[slot] + "\"}";
  }
  json += "]}";
  sendJson(200, json);
}
// WiFiManager owns the access-point portal and STA association.
void startNetwork() {
  diagMark("NETWORK_START_WIFIMANAGER");
  WiFi.onEvent(onWifiEvent);
  wifiManager.setDebugOutput(true);
  wifiManager.setConnectTimeout(25);
  wifiManager.setConfigPortalBlocking(false);
  wifiManager.setWiFiAutoReconnect(true);
  // WiFiManager uses its ESP32-native WiFi credential store, not "irwifi".
  // A saved legacy credential can still be entered through the portal.
  wifiCredentialsSaved = WiFi.SSID().length() > 0;
  const bool initialized = wifiManager.autoConnect(
      ircfg::SETUP_AP_SSID, ircfg::SETUP_AP_PASSWORD);
  stationMode = WiFi.status() == WL_CONNECTED;
  wasStaConnected = stationMode;
  setupApReady = (WiFi.getMode() & WIFI_MODE_AP) != 0;
  wifiAttempted = true;
  wifiAttemptStartedMs = millis();
  diagMark(initialized ? "WIFIMANAGER_AUTOCONNECT" : "WIFIMANAGER_PORTAL");
  if (stationMode && MDNS.begin(ircfg::MDNS_HOST)) {
    MDNS.addService("http", "tcp", 8080);
    mdnsReady = true;
  }
  Serial.printf("WIFI_TRACE event=WIFIMANAGER_READY connected=%d portal=%d sta_ip=%s ir_port=8080\n",
                stationMode ? 1 : 0, setupApReady ? 1 : 0,
                WiFi.localIP().toString().c_str());
}

void maintainNetwork() {
  wifiManager.process(); // Nonblocking portal and station management.
  const bool connected = WiFi.status() == WL_CONNECTED;
  if (connected != wasStaConnected) {
    if (mdnsReady) { MDNS.end(); mdnsReady = false; }
    wasStaConnected = connected;
    if (connected && MDNS.begin(ircfg::MDNS_HOST)) {
      MDNS.addService("http", "tcp", 8080);
      mdnsReady = true;
    }
  }
  stationMode = connected;
  setupApReady = (WiFi.getMode() & WIFI_MODE_AP) != 0;
}

void setupRmt() {
  rxDoneQueue = xQueueCreate(1, sizeof(size_t));
  rmt_rx_channel_config_t rxCfg = {};
  rxCfg.gpio_num = static_cast<gpio_num_t>(ircfg::IR_RX_PIN);
  rxCfg.clk_src = RMT_CLK_SRC_DEFAULT;
  rxCfg.resolution_hz = ircfg::RMT_RESOLUTION_HZ;
  rxCfg.mem_block_symbols = ircfg::MAX_RMT_SYMBOLS;
  rxInitError = rxDoneQueue ? rmt_new_rx_channel(&rxCfg, &rxChannel)
                            : ESP_ERR_NO_MEM;
  if (rxInitError == ESP_OK) {
    rmt_rx_event_callbacks_t callbacks = {};
    callbacks.on_recv_done = onRxDone;
    rxInitError = rmt_rx_register_event_callbacks(rxChannel, &callbacks, rxDoneQueue);
  }
  if (rxInitError == ESP_OK) rxInitError = rmt_enable(rxChannel);
  const bool txOk = rmtInit(
      ircfg::IR_TX_PIN,
      RMT_TX_MODE,
      RMT_MEM_NUM_BLOCKS_2,
      ircfg::RMT_RESOLUTION_HZ);

  rmtRxReady = rxInitError == ESP_OK;
  rmtTxReady = txOk &&
      rmtSetCarrier(ircfg::IR_TX_PIN, true, !ircfg::TX_ACTIVE_HIGH,
                    ircfg::IR_CARRIER_HZ, ircfg::IR_DUTY);
  if (rmtTxReady) {
    rmtSetEOT(ircfg::IR_TX_PIN, ircfg::TX_ACTIVE_HIGH ? 0 : 1);
  }
  Serial.printf("RMT readiness: RX=%d TX=%d RX_INIT_ERR=%d\n", rmtRxReady, rmtTxReady, static_cast<int>(rxInitError));
}

} // namespace

void setup() {
  Serial.begin(115200);
  delay(150);
  diagMark("SETUP_ENTERED");

  fsReady = LittleFS.begin(false);
  diagMark(fsReady ? "FILESYSTEM_READY" : "FILESYSTEM_FAILED");
  if (!fsReady) Serial.println("LittleFS mount failed; automatic formatting disabled");
  alarmsReady = loadAlarmRules();
  Serial.printf("ALARM_STORAGE_READY=%d\n", alarmsReady ? 1 : 0);
  setenv("TZ", "JST-9", 1);
  tzset();

  setupRmt();
  diagMark("IR_INIT_COMPLETE");
  startNetwork();
  setupRoutes();
  diagMark("HTTP_ROUTES_REGISTERED");
  server.begin();
  diagMark("HTTP_SERVER_STARTED");

  const IPAddress ip = stationMode ? WiFi.localIP() : WiFi.softAPIP();
  Serial.printf(
      "IR UI ready: http://%s.local:8080/ or http://%s:8080/\n",
      ircfg::MDNS_HOST,
      ip.toString().c_str());
}

void loop() {
  // Late USB monitors miss setup() events. Emit periodic read-only state.
  static uint32_t lastWifiHeartbeatMs = 0;
  const uint32_t nowMs = millis();
  if (static_cast<uint32_t>(nowMs - lastWifiHeartbeatMs) >= 5000U) {
    Serial.printf("WIFI_DIAG_RESULT t=%lu outcome=%s reason=%ld got_ip=%lu\n", static_cast<unsigned long>(nowMs), wifiOutcome(), static_cast<long>(wifiLastDisconnectReason), static_cast<unsigned long>(wifiGotIpCount));
    lastWifiHeartbeatMs = nowMs;
    Serial.printf("WIFI_TRACE t=%lu event=HEARTBEAT status=%d ap_ready=%d sta_connected=%d credentials=%d disconnect_reason=%ld disconnects=%lu associations=%lu got_ip=%lu retries=%lu ip=%s\n",
                  static_cast<unsigned long>(nowMs), static_cast<int>(WiFi.status()),
                  setupApReady ? 1 : 0, WiFi.status() == WL_CONNECTED ? 1 : 0,
                  wifiCredentialsSaved ? 1 : 0, static_cast<long>(wifiLastDisconnectReason),
                  static_cast<unsigned long>(wifiDisconnectCount),
                  static_cast<unsigned long>(wifiAssociationCount),
                  static_cast<unsigned long>(wifiGotIpCount),
                  static_cast<unsigned long>(staRetryCount),
                  WiFi.localIP().toString().c_str());
  }
  server.handleClient();
  runAlarmClock();
  // WiFiManager polling does not need to run on every HTTP iteration.
  // Keep it responsive while eliminating per-loop portal processing overhead.
  static uint32_t lastNetworkMaintenanceMs = 0;
  const uint32_t networkNowMs = millis();
  if (static_cast<uint32_t>(networkNowMs - lastNetworkMaintenanceMs) >= 25U) {
    lastNetworkMaintenanceMs = networkNowMs;
    maintainNetwork();
  }
  if (rebootAt && static_cast<int32_t>(millis() - rebootAt) >= 0) {
    ESP.restart();
  }
  delay(2);
}

#include <Arduino.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <WebServer.h>
#include <WiFi.h>
#include <WiFiManager.h>
#include <esp32-hal-rmt.h>
#include <driver/rmt_rx.h>
#include <esp_err.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#include <algorithm>
#include <vector>

#include "config.h"
#include "diagnostic_policy.h"
#include "web_ui.h"

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

uint32_t lastTxDurationMs = 0;
uint32_t txAttemptCount = 0;
bool transmitSignal(const Signal &signal) {
  const uint32_t txBeginMs = millis();
  ++txAttemptCount;
  Serial.printf("IR_TX_START t=%lu attempt=%lu pulses=%u ready=%d carrier=%lu\n",
                static_cast<unsigned long>(millis()), static_cast<unsigned long>(txAttemptCount), static_cast<unsigned>(signal.pulses.size()),
                rmtTxReady ? 1 : 0, static_cast<unsigned long>(signal.carrierHz));
  if (!rmtTxReady || signal.pulses.empty()) {
    Serial.println("IR_TX_END result=FAIL reason=not_ready_or_empty");
    return false;
  }

  struct Segment {
    uint16_t duration;
    uint8_t level;
  };
  std::vector<Segment> segments;
  segments.reserve(signal.pulses.size());

  const uint8_t markLevel = ircfg::TX_ACTIVE_HIGH ? 1 : 0;
  const uint8_t spaceLevel = markLevel ? 0 : 1;

  for (const int32_t pulse : signal.pulses) {
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
  const bool accepted = rmtWrite(ircfg::IR_TX_PIN, txSymbols, symbolCount, 1000);
  lastTxDurationMs = millis() - txBeginMs;
  Serial.printf("IR_TX_END result=%s attempt=%lu symbols=%u gpio=%d duration_ms=%lu\n",
                accepted ? "DRIVER_OK" : "FAIL", static_cast<unsigned long>(txAttemptCount),
                static_cast<unsigned>(symbolCount), ircfg::IR_TX_PIN,
                static_cast<unsigned long>(lastTxDurationMs));
  return accepted;
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
  if (!learnSignal(captured, elapsedMs, readAttempts, earlyFailures)) {
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
    json += ",\"early_failures\":" + String(earlyFailures) + "}";
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
  json += "\"stored\":" + String(stored ? "true" : "false") + ",";
  json += "\"slot\":" + String(stored ? slot : -1) + ",";
  json += "\"name\":\"" + jsonEscape(stored ? autoName : String("")) + "\",";
  json += "\"pulses\":" + String(lastSignal.pulses.size()) + ",";
  json += "\"duration_us\":" + String(signalDurationUs(lastSignal)) + ",";
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

void handleSendSaved() {
  int slot = -1;
  if (!parseSlot(slot)) {
    sendJson(400, "{\"ok\":false,\"error\":\"idが不正です\"}");
    return;
  }
  Signal signal;
  if (!loadSignalFromSlot(slot, signal)) {
    sendJson(404, "{\"ok\":false,\"error\":\"信号が見つかりません\"}");
    return;
  }
  if (!transmitSignal(signal)) {
    sendJson(500, "{\"ok\":false,\"error\":\"IR送信に失敗しました\"}");
    return;
  }
  sendJson(200, String("{\"ok\":true,\"result\":\"DRIVER_OK\",\"verified_by_receiver\":false,\"tx_duration_ms\":") + String(lastTxDurationMs) + ",\"tx_attempt\":" + String(txAttemptCount) + "}");
}

void handleSendLast() {
  if (!hasLastSignal) {
    sendJson(409, "{\"ok\":false,\"error\":\"送信できる直近信号がありません\"}");
    return;
  }
  if (!transmitSignal(lastSignal)) {
    sendJson(500, "{\"ok\":false,\"error\":\"IR送信に失敗しました\"}");
    return;
  }
  sendJson(200, "{\"ok\":true,\"result\":\"DRIVER_OK\",\"verified_by_receiver\":false}");
}

void handleDelete() {
  int slot = -1;
  if (!parseSlot(slot)) {
    sendJson(400, "{\"ok\":false,\"error\":\"idが不正です\"}");
    return;
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

void setupRoutes() {
  server.on("/", HTTP_GET, []() {
    server.sendHeader("Cache-Control", "no-store");
    server.send_P(200, "text/html; charset=utf-8", INDEX_HTML);
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

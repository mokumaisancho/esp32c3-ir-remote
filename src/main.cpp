#include <Arduino.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <WebServer.h>
#include <WiFi.h>
#include <esp32-hal-rmt.h>

#include <algorithm>
#include <vector>

#include "config.h"
#include "web_ui.h"

namespace {

constexpr uint32_t SIGNAL_MAGIC = 0x31524945; // "EIR1"
constexpr uint16_t SIGNAL_VERSION = 1;

struct Signal {
  String name;
  std::vector<int32_t> pulses; // +mark / -space, microseconds
  uint32_t carrierHz = ircfg::IR_CARRIER_HZ;
  uint16_t dutyPermille = 300;
};

WebServer server(80);
Signal lastSignal;
bool hasLastSignal = false;
bool stationMode = false;
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

  const String finalPath = signalPath(slot);
  const String tempPath = finalPath + ".tmp";
  LittleFS.remove(tempPath);

  File file = LittleFS.open(tempPath, "w");
  if (!file) return false;

  const uint32_t magic = SIGNAL_MAGIC;
  const uint16_t version = SIGNAL_VERSION;
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

  file.flush();
  file.close();

  if (!ok) {
    LittleFS.remove(tempPath);
    return false;
  }
  LittleFS.remove(finalPath);
  if (!LittleFS.rename(tempPath, finalPath)) {
    LittleFS.remove(tempPath);
    return false;
  }
  return true;
}

bool loadSignalFromSlot(size_t slot, Signal &signal) {
  if (slot >= ircfg::MAX_SIGNAL_SLOTS) return false;
  File file = LittleFS.open(signalPath(slot), "r");
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

  if (!ok || magic != SIGNAL_MAGIC || version != SIGNAL_VERSION ||
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
  file.close();

  signal.name = name;
  signal.pulses = std::move(pulses);
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

bool learnSignal(Signal &signal) {
  size_t symbolCount = ircfg::MAX_RMT_SYMBOLS;
  const bool received =
      rmtRead(ircfg::IR_RX_PIN, rxSymbols, &symbolCount, ircfg::LEARN_WINDOW_MS);
  if (!received || symbolCount == 0) return false;

  signal = normalizeReceived(rxSymbols, symbolCount);
  return signal.pulses.size() >= 6 && signal.pulses.size() <= ircfg::MAX_PULSES;
}

bool transmitSignal(const Signal &signal) {
  if (signal.pulses.empty()) return false;

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
          ircfg::TX_ACTIVE_HIGH,
          signal.carrierHz,
          signal.dutyPermille / 1000.0f)) {
    return false;
  }
  rmtSetEOT(ircfg::IR_TX_PIN, spaceLevel);
  return rmtWrite(ircfg::IR_TX_PIN, txSymbols, symbolCount, 1000);
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
  const IPAddress ip = stationMode ? WiFi.localIP() : WiFi.softAPIP();
  String json = "{";
  json += "\"ok\":true,";
  json += "\"profile\":\"" + jsonEscape(ircfg::PROFILE_NAME) + "\",";
  json += "\"network_mode\":\"" + String(stationMode ? "STA" : "AP") + "\",";
  json += "\"ip\":\"" + ip.toString() + "\",";
  json += "\"hostname\":\"" + String(ircfg::MDNS_HOST) + ".local\",";
  json += "\"rx_gpio\":" + String(ircfg::IR_RX_PIN) + ",";
  json += "\"tx_gpio\":" + String(ircfg::IR_TX_PIN) + ",";
  json += "\"carrier_hz\":" + String(ircfg::IR_CARRIER_HZ) + ",";
  json += "\"duty\":" + String(ircfg::IR_DUTY, 2) + ",";
  json += "\"has_last\":" + String(hasLastSignal ? "true" : "false");
  json += "}";
  sendJson(200, json);
}

void handleLearn() {
  Signal captured;
  if (!learnSignal(captured)) {
    sendJson(408, "{\"ok\":false,\"error\":\"5秒以内に有効なIR信号を受信できませんでした\"}");
    return;
  }
  lastSignal = std::move(captured);
  hasLastSignal = true;

  // Persist the RAW waveform before acknowledging the learning request.
  // Never overwrite a user-named slot. A full or unavailable LittleFS store
  // must be explicitly reported, not silently represented as a saved signal.
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
  sendJson(200, "{\"ok\":true}");
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
  sendJson(200, "{\"ok\":true}");
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
  const bool ok =
      prefs.putString("ssid", ssid) > 0 &&
      prefs.putString("pass", password) >= 0;
  prefs.end();

  if (!ok) {
    sendJson(500, "{\"ok\":false,\"error\":\"Wi-Fi設定保存に失敗しました\"}");
    return;
  }
  sendJson(200, "{\"ok\":true,\"rebooting\":true}");
  rebootAt = millis() + 1200;
}

void setupRoutes() {
  server.on("/", HTTP_GET, []() {
    server.sendHeader("Cache-Control", "no-store");
    server.send_P(200, "text/html; charset=utf-8", INDEX_HTML);
  });
  server.on("/api/status", HTTP_GET, handleStatus);
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

bool connectStoredWifi() {
  Preferences prefs;
  if (!prefs.begin("irwifi", true)) return false;
  const String ssid = prefs.getString("ssid", "");
  const String password = prefs.getString("pass", "");
  prefs.end();
  if (ssid.isEmpty()) return false;

  WiFi.mode(WIFI_STA);
  WiFi.setHostname(ircfg::MDNS_HOST);
  WiFi.begin(ssid.c_str(), password.c_str());

  const uint32_t deadline = millis() + 12000;
  while (WiFi.status() != WL_CONNECTED &&
         static_cast<int32_t>(deadline - millis()) > 0) {
    delay(100);
  }
  return WiFi.status() == WL_CONNECTED;
}

void startNetwork() {
  stationMode = connectStoredWifi();
  if (!stationMode) {
    WiFi.disconnect(true, true);
    delay(100);
    WiFi.mode(WIFI_AP);
    WiFi.softAP(ircfg::SETUP_AP_SSID, ircfg::SETUP_AP_PASSWORD);
  }

  if (MDNS.begin(ircfg::MDNS_HOST)) {
    MDNS.addService("http", "tcp", 80);
  }
}

void setupRmt() {
  const bool rxOk = rmtInit(
      ircfg::IR_RX_PIN,
      RMT_RX_MODE,
      RMT_MEM_NUM_BLOCKS_2,
      ircfg::RMT_RESOLUTION_HZ);
  const bool txOk = rmtInit(
      ircfg::IR_TX_PIN,
      RMT_TX_MODE,
      RMT_MEM_NUM_BLOCKS_2,
      ircfg::RMT_RESOLUTION_HZ);

  if (!rxOk || !txOk) {
    Serial.println("RMT init failed");
    return;
  }

  rmtSetRxMinThreshold(ircfg::IR_RX_PIN, ircfg::RX_GLITCH_FILTER_US);
  rmtSetRxMaxThreshold(ircfg::IR_RX_PIN, ircfg::RX_IDLE_THRESHOLD_US);
  rmtSetCarrier(
      ircfg::IR_TX_PIN,
      true,
      ircfg::TX_ACTIVE_HIGH,
      ircfg::IR_CARRIER_HZ,
      ircfg::IR_DUTY);
  rmtSetEOT(ircfg::IR_TX_PIN, ircfg::TX_ACTIVE_HIGH ? 0 : 1);
}

} // namespace

void setup() {
  Serial.begin(115200);
  delay(150);

  if (!LittleFS.begin(true)) {
    Serial.println("LittleFS mount failed");
  }

  setupRmt();
  startNetwork();
  setupRoutes();
  server.begin();

  const IPAddress ip = stationMode ? WiFi.localIP() : WiFi.softAPIP();
  Serial.printf(
      "IR UI ready: http://%s.local/ or http://%s/\n",
      ircfg::MDNS_HOST,
      ip.toString().c_str());
}

void loop() {
  server.handleClient();
  if (rebootAt && static_cast<int32_t>(millis() - rebootAt) >= 0) {
    ESP.restart();
  }
  delay(2);
}

#pragma once
// Included within main.cpp's anonymous namespace after the IR send implementation.
// Time-zone policy is intentionally explicit: all schedules use Japan Standard Time.
// Requires <ctime> and weekly_alarm_logic.h included by main.cpp.

constexpr uint8_t WEEKLY_RULE_LIMIT = 12;
constexpr uint32_t WEEKLY_MAGIC = 0x314C4157U; // WAL1
constexpr uint16_t WEEKLY_VERSION = 1;
constexpr const char *WEEKLY_FILE = "/weekly.bin";
constexpr const char *WEEKLY_TEMP = "/weekly.tmp";
constexpr const char *WEEKLY_BAK = "/weekly.bak";
constexpr time_t WEEKLY_EPOCH_MIN = 1735689600; // 2025-01-01 UTC

struct WeeklyRule {
  uint16_t minute = 0;
  uint8_t days = 0;         // bit0=Mon, ..., bit6=Sun
  uint8_t slot = 255;       // 255 means empty
  uint8_t enabled = 0;
  uint32_t lastFiredDay = 0;
  uint32_t fingerprint = 0;
};
WeeklyRule weeklyRules[WEEKLY_RULE_LIMIT];
bool weeklyClockSynced = false;
uint32_t weeklyLastPollMs = 0;
uint32_t weeklyBlockedDay[WEEKLY_RULE_LIMIT] = {};
String weeklyLastOutcome = "NOT_STARTED";

uint32_t weeklyMix(uint32_t hash, const void *data, size_t n) {
  const auto *bytes = reinterpret_cast<const uint8_t *>(data);
  for (size_t i = 0; i < n; ++i) {
    hash ^= bytes[i];
    hash *= 16777619U;
  }
  return hash;
}
uint32_t weeklySignalSignature(const Signal &signal) {
  uint32_t hash = 2166136261U;
  hash = weeklyMix(hash, &signal.carrierHz, sizeof(signal.carrierHz));
  hash = weeklyMix(hash, &signal.dutyPermille, sizeof(signal.dutyPermille));
  const uint16_t n = static_cast<uint16_t>(signal.pulses.size());
  hash = weeklyMix(hash, &n, sizeof(n));
  for (int32_t pulse : signal.pulses) hash = weeklyMix(hash, &pulse, sizeof(pulse));
  const uint8_t extra = static_cast<uint8_t>(signal.extraFrames.size());
  hash = weeklyMix(hash, &extra, sizeof(extra));
  for (size_t i = 0; i < signal.extraFrames.size(); ++i) {
    const uint32_t gap = signal.interFrameGapUs[i];
    hash = weeklyMix(hash, &gap, sizeof(gap));
    for (int32_t pulse : signal.extraFrames[i]) hash = weeklyMix(hash, &pulse, sizeof(pulse));
  }
  return hash;
}
bool weeklyWriteField(File &file, uint32_t &hash, const void *data, size_t n) {
  if (!writeExact(file, data, n)) return false;
  hash = weeklyMix(hash, data, n);
  return true;
}
bool weeklyReadField(File &file, uint32_t &hash, void *data, size_t n) {
  if (!readExact(file, data, n)) return false;
  hash = weeklyMix(hash, data, n);
  return true;
}
bool weeklyReadAt(const char *path, WeeklyRule *out) {
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  const size_t expected = 4 + 2 + 1 + WEEKLY_RULE_LIMIT * (2 + 1 + 1 + 1 + 4 + 4) + 4;
  if (f.size() != expected) { f.close(); return false; }
  uint32_t hash = 2166136261U, magic = 0;
  uint16_t version = 0;
  uint8_t limit = 0;
  bool ok = weeklyReadField(f, hash, &magic, sizeof(magic)) &&
            weeklyReadField(f, hash, &version, sizeof(version)) &&
            weeklyReadField(f, hash, &limit, sizeof(limit));
  if (!ok || magic != WEEKLY_MAGIC || version != WEEKLY_VERSION ||
      limit != WEEKLY_RULE_LIMIT) { f.close(); return false; }
  for (uint8_t i = 0; i < WEEKLY_RULE_LIMIT && ok; ++i) {
    WeeklyRule &r = out[i];
    ok = weeklyReadField(f, hash, &r.minute, sizeof(r.minute)) &&
         weeklyReadField(f, hash, &r.days, sizeof(r.days)) &&
         weeklyReadField(f, hash, &r.slot, sizeof(r.slot)) &&
         weeklyReadField(f, hash, &r.enabled, sizeof(r.enabled)) &&
         weeklyReadField(f, hash, &r.lastFiredDay, sizeof(r.lastFiredDay)) &&
         weeklyReadField(f, hash, &r.fingerprint, sizeof(r.fingerprint));
    if (!ok) break;
    if (r.slot != 255 &&
        (!weekly_alarm::validRule(r.days, r.minute, r.slot, ircfg::MAX_SIGNAL_SLOTS) ||
         r.enabled > 1)) ok = false;
    if (r.slot == 255 && r.enabled) ok = false;
  }
  uint32_t expectedHash = 0;
  if (ok) ok = readExact(f, &expectedHash, sizeof(expectedHash));
  f.close();
  return ok && expectedHash == hash;
}
bool weeklyLoad() {
  if (!fsReady) return false;
  WeeklyRule loaded[WEEKLY_RULE_LIMIT] = {};
  if (weeklyReadAt(WEEKLY_FILE, loaded)) {
    memcpy(weeklyRules, loaded, sizeof(weeklyRules));
    return true;
  }
  // A previous interrupted atomic rename may have left a valid backup.
  if (weeklyReadAt(WEEKLY_BAK, loaded)) {
    memcpy(weeklyRules, loaded, sizeof(weeklyRules));
    if (!LittleFS.exists(WEEKLY_FILE))
      LittleFS.rename(WEEKLY_BAK, WEEKLY_FILE);
    return true;
  }
  // Never interpret corrupt schedules as active; do not format or erase flash.
  return false;
}
bool weeklyPersist() {
  if (!fsReady) return false;
  LittleFS.remove(WEEKLY_TEMP);
  File f = LittleFS.open(WEEKLY_TEMP, "w");
  if (!f) return false;
  uint32_t hash = 2166136261U;
  const uint32_t magic = WEEKLY_MAGIC;
  const uint16_t version = WEEKLY_VERSION;
  const uint8_t limit = WEEKLY_RULE_LIMIT;
  bool ok = weeklyWriteField(f, hash, &magic, sizeof(magic)) &&
            weeklyWriteField(f, hash, &version, sizeof(version)) &&
            weeklyWriteField(f, hash, &limit, sizeof(limit));
  for (uint8_t i = 0; i < WEEKLY_RULE_LIMIT && ok; ++i) {
    const WeeklyRule &r = weeklyRules[i];
    ok = weeklyWriteField(f, hash, &r.minute, sizeof(r.minute)) &&
         weeklyWriteField(f, hash, &r.days, sizeof(r.days)) &&
         weeklyWriteField(f, hash, &r.slot, sizeof(r.slot)) &&
         weeklyWriteField(f, hash, &r.enabled, sizeof(r.enabled)) &&
         weeklyWriteField(f, hash, &r.lastFiredDay, sizeof(r.lastFiredDay)) &&
         weeklyWriteField(f, hash, &r.fingerprint, sizeof(r.fingerprint));
  }
  if (ok) ok = writeExact(f, &hash, sizeof(hash));
  f.flush();
  f.close();
  if (!ok) { LittleFS.remove(WEEKLY_TEMP); return false; }

  LittleFS.remove(WEEKLY_BAK);
  const bool hadFile = LittleFS.exists(WEEKLY_FILE);
  if (hadFile && !LittleFS.rename(WEEKLY_FILE, WEEKLY_BAK)) {
    LittleFS.remove(WEEKLY_TEMP);
    return false;
  }
  if (!LittleFS.rename(WEEKLY_TEMP, WEEKLY_FILE)) {
    if (hadFile) LittleFS.rename(WEEKLY_BAK, WEEKLY_FILE);
    LittleFS.remove(WEEKLY_TEMP);
    return false;
  }
  if (hadFile) LittleFS.remove(WEEKLY_BAK);
  return true;
}
bool weeklyClock(std::tm &local) {
  const time_t now = time(nullptr);
  // The ESP32-C3 has no battery-backed clock. Accept the clock only after
  // this boot has seen both Wi-Fi and a plausible NTP-set Unix epoch.
  if (!weeklyClockSynced && WiFi.status() == WL_CONNECTED && now >= WEEKLY_EPOCH_MIN)
    weeklyClockSynced = true;
  return weeklyClockSynced && now >= WEEKLY_EPOCH_MIN &&
         localtime_r(&now, &local) != nullptr;
}
bool weeklyParseUint(const String &raw, unsigned max, unsigned &out) {
  if (raw.isEmpty() || raw.length() > 5) return false;
  unsigned value = 0;
  for (size_t i = 0; i < raw.length(); ++i) {
    if (raw[i] < '0' || raw[i] > '9') return false;
    value = value * 10U + static_cast<unsigned>(raw[i] - '0');
    if (value > max) return false;
  }
  out = value;
  return true;
}
bool weeklyParseTime(const String &raw, uint16_t &minute) {
  if (raw.length() != 5 || raw[2] != ':') return false;
  const String hh = raw.substring(0, 2), mm = raw.substring(3, 5);
  unsigned h = 0, m = 0;
  if (!weeklyParseUint(hh, 23, h) || !weeklyParseUint(mm, 59, m)) return false;
  minute = static_cast<uint16_t>(h * 60 + m);
  return true;
}
void weeklyInit() {
  if (weeklyLoad()) {
    Serial.println("WEEKLY_ALARMS_LOADED");
  } else {
    // New firmware: missing schedules is expected. Existing corrupt file
    // is left intact for recovery and no invalid rules will be executed.
    Serial.println("WEEKLY_ALARMS_EMPTY_OR_INVALID");
  }
  // configTzTime is non-blocking; SNTP will synchronize when Wi-Fi is available.
  configTzTime("JST-9", "ntp.nict.jp", "time.google.com", "pool.ntp.org");
  weeklyLastOutcome = "WAITING_FOR_NTP";
}
void weeklyPoll() {
  const uint32_t nowMs = millis();
  if (static_cast<uint32_t>(nowMs - weeklyLastPollMs) < 500U) return;
  weeklyLastPollMs = nowMs;
  std::tm local = {};
  if (!weeklyClock(local)) return;
  const uint32_t day = weekly_alarm::civilDayKey(local);
  for (uint8_t i = 0; i < WEEKLY_RULE_LIMIT; ++i) {
    WeeklyRule &r = weeklyRules[i];
    if (r.slot == 255 || weeklyBlockedDay[i] == day ||
        !weekly_alarm::due(r.days, r.minute, r.enabled, r.lastFiredDay, local))
      continue;
    // Persist the occurrence BEFORE emitting IR. Prevent duplicate actions
    // after power loss/reboot in the same minute, and upon clock corrections.
    const uint32_t previousDay = r.lastFiredDay;
    r.lastFiredDay = day;
    if (!weeklyPersist()) {
      r.lastFiredDay = previousDay;
      weeklyBlockedDay[i] = day;  // Do not hammer LittleFS every 500ms after failure.
      weeklyLastOutcome = "PERSIST_FAILED";
      Serial.printf("WEEKLY_ALARM_BLOCKED id=%u reason=persistence\n", i);
      continue;
    }
    Signal command;
    if (!loadSignalFromSlot(r.slot, command) ||
        weeklySignalSignature(command) != r.fingerprint) {
      weeklyLastOutcome = "SIGNAL_MISSING_OR_CHANGED";
      Serial.printf("WEEKLY_ALARM_BLOCKED id=%u reason=signal_changed\n", i);
      continue;
    }
    const uint32_t startedMs = millis();
    const bool result = transmitSignal(command);
    weeklyLastOutcome = result ? "SENT_DRIVER_OK" : "RMT_FAILED";
    Serial.printf("WEEKLY_ALARM id=%u slot=%u local_day=%lu minute=%u result=%s elapsed_ms=%lu\n",
                  i, r.slot, static_cast<unsigned long>(day), r.minute,
                  result ? "DRIVER_OK" : "FAIL",
                  static_cast<unsigned long>(millis() - startedMs));
  }
}
void handleWeeklyGet() {
  std::tm local = {};
  const bool synced = weeklyClock(local);
  char nowText[24] = {};
  if (synced)
    snprintf(nowText, sizeof(nowText), "%04d-%02d-%02d %02d:%02d:%02d",
             local.tm_year + 1900, local.tm_mon + 1, local.tm_mday,
             local.tm_hour, local.tm_min, local.tm_sec);
  String json = "{\"ok\":true,\"timezone\":\"Asia/Tokyo\",\"clock_synced\":";
  json += synced ? "true" : "false";
  json += ",\"now\":\"" + String(nowText) + "\",\"last_outcome\":\"" +
          jsonEscape(weeklyLastOutcome) + "\",\"rules\":[";
  bool first = true;
  for (uint8_t i = 0; i < WEEKLY_RULE_LIMIT; ++i) {
    const WeeklyRule &r = weeklyRules[i];
    if (r.slot == 255) continue;
    if (!first) json += ",";
    first = false;
    char hhmm[6];
    snprintf(hhmm, sizeof(hhmm), "%02u:%02u", r.minute / 60, r.minute % 60);
    Signal signal;
    const bool exists = loadSignalFromSlot(r.slot, signal);
    const bool valid = exists && weeklySignalSignature(signal) == r.fingerprint;
    json += "{\"id\":" + String(i) + ",\"time\":\"" + String(hhmm) + "\"";
    json += ",\"days\":" + String(r.days);
    json += ",\"signal_slot\":" + String(r.slot);
    json += ",\"signal_name\":\"" + jsonEscape(exists ? signal.name : String("未登録")) + "\"";
    json += ",\"signal_valid\":" + String(valid ? "true" : "false");
    json += ",\"enabled\":" + String(r.enabled ? "true" : "false") + "}";
  }
  json += "]}";
  sendJson(200, json);
}
void handleWeeklySet() {
  unsigned days = 0, slot = 0;
  uint16_t minute = 0;
  if (!weeklyParseUint(server.arg("days"), 127, days) || days == 0 ||
      !weeklyParseUint(server.arg("signal_slot"), ircfg::MAX_SIGNAL_SLOTS - 1, slot) ||
      !weeklyParseTime(server.arg("time"), minute) ||
      (server.arg("enabled") != "0" && server.arg("enabled") != "1")) {
    sendJson(400, "{\"ok\":false,\"error\":\"曜日・時刻・信号・有効設定が不正です\"}");
    return;
  }
  Signal signal;
  if (!loadSignalFromSlot(slot, signal)) {
    sendJson(404, "{\"ok\":false,\"error\":\"保存済み信号が見つかりません\"}");
    return;
  }
  int id = -1;
  if (server.hasArg("id") && server.arg("id") != "-1") {
    unsigned parsed = 0;
    if (!weeklyParseUint(server.arg("id"), WEEKLY_RULE_LIMIT - 1, parsed) ||
        weeklyRules[parsed].slot == 255) {
      sendJson(400, "{\"ok\":false,\"error\":\"変更対象の予定が存在しません\"}");
      return;
    }
    id = static_cast<int>(parsed);
  } else {
    for (uint8_t i = 0; i < WEEKLY_RULE_LIMIT; ++i) {
      if (weeklyRules[i].slot == 255) { id = i; break; }
    }
  }
  if (id < 0) {
    sendJson(507, "{\"ok\":false,\"error\":\"最大12件まで登録できます\"}");
    return;
  }
  const WeeklyRule old = weeklyRules[id];
  WeeklyRule &r = weeklyRules[id];
  r.days = static_cast<uint8_t>(days);
  r.minute = minute;
  r.slot = static_cast<uint8_t>(slot);
  r.enabled = server.arg("enabled") == "1" ? 1 : 0;
  r.fingerprint = weeklySignalSignature(signal);
  r.lastFiredDay = 0; // Changing a schedule explicitly re-arms it.
  weeklyBlockedDay[id] = 0;
  if (!weeklyPersist()) {
    r = old;
    sendJson(500, "{\"ok\":false,\"error\":\"予定をLittleFSに保存できません\"}");
    return;
  }
  sendJson(200, "{\"ok\":true,\"id\":" + String(id) + "}");
}
void handleWeeklyDelete() {
  unsigned id = 0;
  if (!weeklyParseUint(server.arg("id"), WEEKLY_RULE_LIMIT - 1, id) ||
      weeklyRules[id].slot == 255) {
    sendJson(400, "{\"ok\":false,\"error\":\"削除対象がありません\"}");
    return;
  }
  const WeeklyRule old = weeklyRules[id];
  weeklyRules[id] = WeeklyRule{};
  weeklyBlockedDay[id] = 0;
  if (!weeklyPersist()) {
    weeklyRules[id] = old;
    sendJson(500, "{\"ok\":false,\"error\":\"予定を削除できません\"}");
    return;
  }
  sendJson(200, "{\"ok\":true}");
}
bool weeklyForgetSignal(int slot) {
  WeeklyRule old[WEEKLY_RULE_LIMIT];
  memcpy(old, weeklyRules, sizeof(weeklyRules));
  bool changed = false;
  for (auto &r : weeklyRules) {
    if (r.slot == slot) { r = WeeklyRule{}; changed = true; }
  }
  if (!changed) return true;
  if (weeklyPersist()) return true;
  memcpy(weeklyRules, old, sizeof(weeklyRules));
  return false; // Fingerprints prevent an old rule from controlling a replacement.
}

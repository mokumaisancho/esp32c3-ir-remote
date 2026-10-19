#pragma once
// Deterministic, Arduino-independent weekly alarm rules and on-disk format.
// Weekday bits: Sunday=0, Monday=1, ... Saturday=6. JST is resolved by caller.
#include <array>
#include <cstddef>
#include <cstdint>

namespace alarm_policy {
constexpr size_t kMaxRules = 16;
constexpr size_t kSlots = 32;
constexpr size_t kHeaderSize = 6;
constexpr size_t kRecordSize = 10;
constexpr size_t kFileSize = kHeaderSize + kMaxRules * kRecordSize + 4;
using Bytes = std::array<uint8_t, kFileSize>;

struct Rule {
  uint8_t days = 0;        // bit 0 Sunday through bit 6 Saturday
  uint8_t hour = 0;        // 0..23
  uint8_t minute = 0;      // 0..59
  uint8_t slot = 0;        // Saved LittleFS IR signal, 0..31
  uint8_t enabled = 0;     // 0 or 1
  uint8_t firstOnly = 0;   // 0 whole signal, 1 only first frame
  uint32_t lastMinute = 0; // UTC epoch minute; persisted to avoid reboot duplicates
};
using Rules = std::array<Rule, kMaxRules>;

inline bool valid(const Rule &r) {
  return r.days < 128 && r.hour < 24 && r.minute < 60 &&
         r.slot < kSlots && r.enabled <= 1 && r.firstOnly <= 1 &&
         (r.days != 0 || (!r.enabled && !r.firstOnly));
}

inline bool due(const Rule &r, int weekday, int hour, int minute, uint32_t epochMinute) {
  return epochMinute >= 28000000U && r.enabled && r.days &&
         weekday >= 0 && weekday < 7 && hour >= 0 && hour < 24 &&
         minute >= 0 && minute < 60 &&
         (r.days & (1U << weekday)) != 0 &&
         r.hour == hour && r.minute == minute && r.lastMinute != epochMinute;
}

inline uint32_t checksum(const uint8_t *data, size_t n) {
  uint32_t value = 2166136261U;
  for (size_t i = 0; i < n; ++i) {
    value ^= data[i];
    value *= 16777619U;
  }
  return value;
}
inline void write32(uint8_t *p, uint32_t n) {
  for (size_t i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(n >> (8 * i));
}
inline uint32_t read32(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) |
         (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}
inline Bytes encode(const Rules &rules) {
  Bytes bytes{};
  bytes[0] = 'I'; bytes[1] = 'R'; bytes[2] = 'A'; bytes[3] = 'L';
  bytes[4] = 1; bytes[5] = static_cast<uint8_t>(kMaxRules);
  for (size_t i = 0; i < kMaxRules; ++i) {
    const auto &r = rules[i];
    uint8_t *p = bytes.data() + kHeaderSize + i * kRecordSize;
    p[0] = r.days; p[1] = r.hour; p[2] = r.minute;
    p[3] = r.slot; p[4] = r.enabled; p[5] = r.firstOnly;
    write32(p + 6, r.lastMinute);
  }
  write32(bytes.data() + kFileSize - 4, checksum(bytes.data(), kFileSize - 4));
  return bytes;
}
inline bool decode(const uint8_t *bytes, size_t n, Rules &rules) {
  if (n != kFileSize || bytes[0] != 'I' || bytes[1] != 'R' ||
      bytes[2] != 'A' || bytes[3] != 'L' || bytes[4] != 1 ||
      bytes[5] != kMaxRules ||
      read32(bytes + kFileSize - 4) != checksum(bytes, kFileSize - 4))
    return false;
  Rules recovered{};
  for (size_t i = 0; i < kMaxRules; ++i) {
    const uint8_t *p = bytes + kHeaderSize + i * kRecordSize;
    Rule &r = recovered[i];
    r.days = p[0]; r.hour = p[1]; r.minute = p[2];
    r.slot = p[3]; r.enabled = p[4]; r.firstOnly = p[5];
    r.lastMinute = read32(p + 6);
    if (!valid(r)) return false;
  }
  rules = recovered;
  return true;
}
}  // namespace alarm_policy

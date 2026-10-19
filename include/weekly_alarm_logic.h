#pragma once
#include <cstdint>
#include <ctime>

// Bit 0 = Monday, ... bit 6 = Sunday. Uses local civil time, not UTC.
namespace weekly_alarm {
inline uint8_t mondayBasedWeekday(int tmWday) {
  return static_cast<uint8_t>((tmWday + 6) % 7);
}
inline uint32_t civilDayKey(const std::tm &local) {
  return static_cast<uint32_t>(local.tm_year + 1900) * 1000U +
         static_cast<uint32_t>(local.tm_yday + 1);
}
inline bool validRule(uint8_t days, uint16_t minuteOfDay, uint8_t slot, uint8_t slotLimit) {
  return days > 0 && (days & 0x80U) == 0 &&
         minuteOfDay < 24U * 60U && slot < slotLimit;
}
inline bool due(uint8_t days, uint16_t minuteOfDay, bool enabled,
                uint32_t lastFiredDay, const std::tm &local) {
  if (!enabled || local.tm_wday < 0 || local.tm_wday > 6) return false;
  if (!validRule(days, minuteOfDay, 0, 1)) return false;
  const uint8_t day = mondayBasedWeekday(local.tm_wday);
  return (days & (1U << day)) != 0 &&
         minuteOfDay == static_cast<uint16_t>(local.tm_hour * 60 + local.tm_min) &&
         lastFiredDay != civilDayKey(local);
}
} // namespace weekly_alarm

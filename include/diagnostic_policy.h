#pragma once
#include <stdint.h>
namespace irpolicy {
inline bool retryDue(uint32_t now, uint32_t last, uint32_t interval) {
  return static_cast<uint32_t>(now - last) >= interval;
}
inline const char *rxFailureReason(bool startFailed, bool resetFailed,
                                   uint32_t symbolCount) {
  return startFailed ? "rmt_start_failed" :
         resetFailed ? "rmt_reset_failed" :
         symbolCount > 0 ? "invalid_frame" : "rx_timeout";
}
}

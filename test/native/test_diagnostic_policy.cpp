#include "diagnostic_policy.h"
#include <cassert>
#include <cstring>
#include <cstdint>
int main() {
  using namespace irpolicy;
  assert(!retryDue(14999, 0, 15000));
  assert(retryDue(15000, 0, 15000));
  assert(!retryDue(20000, 10000, 15000));
  assert(retryDue(5, UINT32_MAX - 15000, 15000));
  assert(std::strcmp(rxFailureReason(true, false, 0), "rmt_start_failed") == 0);
  assert(std::strcmp(rxFailureReason(false, true, 0), "rmt_reset_failed") == 0);
  assert(std::strcmp(rxFailureReason(false, false, 3), "invalid_frame") == 0);
  assert(std::strcmp(rxFailureReason(false, false, 0), "rx_timeout") == 0);
  assert(std::strcmp(rxFailureReason(true, true, 3), "rmt_start_failed") == 0);
  return 0;
}

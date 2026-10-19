#include "alarm_policy.h"

#include <cassert>
#include <cstdio>
using namespace alarm_policy;

int main() {
  static_assert(kFileSize == 170, "Do not silently change persisted record size");
  Rules rules{};
  Rule &r = rules[3];
  r.days = (1U << 1) | (1U << 3) | (1U << 5); // Mon/Wed/Fri
  r.hour = 7; r.minute = 15; r.slot = 12;
  r.enabled = 1; r.firstOnly = 1;
  assert(valid(r));
  assert(due(r, 1, 7, 15, 30000000));          // Monday, 07:15
  assert(due(r, 3, 7, 15, 30000000));          // Wednesday
  assert(!due(r, 0, 7, 15, 30000000));         // Sunday not selected
  assert(!due(r, 1, 7, 14, 30000000));         // wrong minute
  assert(!due(r, 1, 8, 15, 30000000));         // wrong hour
  assert(!due(r, 1, 7, 15, 2));                // invalid epoch
  r.lastMinute = 30000000;
  assert(!due(r, 1, 7, 15, 30000000));         // no duplicates
  assert(due(r, 1, 7, 15, 30010080));          // one week later
  r.enabled = 0;
  assert(!due(r, 1, 7, 15, 30010080));         // disabled
  r.enabled = 1;
  auto buffer = encode(rules);
  Rules decoded{};
  assert(decode(buffer.data(), buffer.size(), decoded));
  assert(decoded[3].lastMinute == 30000000);
  assert(decoded[3].firstOnly == 1 && decoded[3].slot == 12);
  assert(decoded[3].days == r.days);
  assert(!decode(buffer.data(), buffer.size() - 1, decoded)); // truncated
  buffer[15] ^= 0x01;
  assert(!decode(buffer.data(), buffer.size(), decoded));    // CRC
  buffer = encode(rules);
  buffer[6 + 3 * kRecordSize + 1] = 24; // invalid hour
  write32(buffer.data() + kFileSize - 4, checksum(buffer.data(), kFileSize - 4));
  assert(!decode(buffer.data(), buffer.size(), decoded));   // semantic corruption
  r.hour = 24;
  assert(!valid(r));
  r.hour = 7;
  r.slot = 32;
  assert(!valid(r));
  std::puts("ALARM_POLICY_ALL_CASES_PASS");
  return 0;
}

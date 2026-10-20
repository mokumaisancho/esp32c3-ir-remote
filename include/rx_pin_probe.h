#pragma once
#include <stdint.h>

// A protocol-independent GPIO-level observation.  It deliberately does not
// decode IR commands: it asks whether the receiver output actually changes.
namespace rx_pin_probe {
struct Counters {
  uint32_t samples = 0;
  uint32_t high_samples = 0;
  uint32_t low_samples = 0;
  uint32_t transitions = 0;
  uint32_t falling_edges = 0;
  uint32_t rising_edges = 0;
  uint32_t longest_sample_gap_us = 0;
  int8_t initial_level = -1;
  int8_t final_level = -1;
  uint32_t first_transition_sample = 0;

  void observe(int level, uint32_t interval_us = 0) {
    const int8_t value = level ? 1 : 0;
    if (interval_us > longest_sample_gap_us)
      longest_sample_gap_us = interval_us;
    if (samples == 0) initial_level = value;
    else if (final_level != value) {
      ++transitions;
      if (first_transition_sample == 0) first_transition_sample = samples;
      if (value == 0) ++falling_edges;
      else ++rising_edges;
    }
    final_level = value;
    if (value) ++high_samples;
    else ++low_samples;
    ++samples;
  }
};
} // namespace rx_pin_probe

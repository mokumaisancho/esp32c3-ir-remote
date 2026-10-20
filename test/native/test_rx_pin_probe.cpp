#include "rx_pin_probe.h"
#include <cassert>
#include <iostream>
int main() {
  rx_pin_probe::Counters idle;
  for (unsigned i = 0; i < 10000; ++i) idle.observe(1, 12);
  assert(idle.samples == 10000);
  assert(idle.initial_level == 1 && idle.final_level == 1);
  assert(idle.high_samples == idle.samples && idle.low_samples == 0);
  assert(idle.transitions == 0 && idle.longest_sample_gap_us == 12);
  rx_pin_probe::Counters signal;
  const int sequence[] = {1,1,1,0,0,0,1,1,0,0,1};
  for (int level : sequence) signal.observe(level, 14);
  assert(signal.samples == sizeof(sequence)/sizeof(sequence[0]));
  assert(signal.transitions == 4 && signal.falling_edges == 2 && signal.rising_edges == 2);
  assert(signal.initial_level == 1 && signal.final_level == 1);
  assert(signal.high_samples == 6 && signal.low_samples == 5);
  assert(signal.first_transition_sample == 3);
  signal.observe(1, 2200);
  assert(signal.longest_sample_gap_us == 2200);
  rx_pin_probe::Counters stuck_low;
  for (int i = 0; i < 900; ++i) stuck_low.observe(0);
  assert(stuck_low.transitions == 0 && stuck_low.low_samples == 900);
  std::cout << "RX_PIN_PROBE_SIGNAL_AND_NEGATIVE_CONTROLS_PASS\n";
}

#pragma once

#include <Arduino.h>
#include <esp32-hal-rmt.h>

namespace ircfg {

constexpr int IR_RX_PIN = 5;   // Vishay TSOP38238 OUT
constexpr int IR_TX_PIN = 7;   // IR transmitter DAT

constexpr uint32_t RMT_RESOLUTION_HZ = 1000000; // 1 tick = 1 us
constexpr uint32_t IR_CARRIER_HZ = 38000;
constexpr float IR_DUTY = 0.30f;

// TSOP38238 output is active-low: LOW = IR mark, HIGH = space.
constexpr bool RX_ACTIVE_LOW = true;

// Generic IR transmitter module is assumed active-high on DAT.
constexpr bool TX_ACTIVE_HIGH = true;

constexpr uint32_t LEARN_WINDOW_MS = 5000;
constexpr uint16_t RX_IDLE_THRESHOLD_US = 15000;
constexpr uint8_t RX_GLITCH_FILTER_US = 80;

constexpr size_t RMT_BLOCKS = 2;
constexpr size_t MAX_RMT_SYMBOLS = RMT_SYMBOLS_PER_CHANNEL_BLOCK * RMT_BLOCKS;
constexpr size_t MAX_PULSES = MAX_RMT_SYMBOLS * 2;
constexpr size_t MAX_SIGNAL_SLOTS = 32;
constexpr size_t MAX_NAME_BYTES = 96;

constexpr char PROFILE_NAME[] = "ODELIC NRL-351N-JP";
constexpr char MDNS_HOST[] = "esp32-ir";
constexpr char SETUP_AP_SSID[] = "ESP32C3-IR-Setup";
constexpr char SETUP_AP_PASSWORD[] = "esp32ir35";

} // namespace ircfg

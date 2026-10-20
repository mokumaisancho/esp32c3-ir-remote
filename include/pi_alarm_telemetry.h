#pragma once
// Low-footprint, best-effort LAN alarm event probe.
// No OAuth, HTTP, TLS or SSH on ESP32-C3. Sender never opens a listener.
// Receiver must bind on a private Pi interface with a strict IP allowlist.
// IMPORTANT: UDP source-IP allowlist is not cryptographic authentication.
// Do not expose port 5514 to the Internet or accept sensitive payloads.
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <esp_system.h>
#include <ctime>

namespace pi_alarm_telemetry {
constexpr uint16_t PORT = 5514;
constexpr IPAddress PI_HOST(192, 168, 2, 131);
inline uint32_t bootId() {
  static const uint32_t id = esp_random();
  return id;
}
inline void emit(const char* phase, uint8_t rule, uint8_t slot,
                 int result, uint32_t durationMs, uint32_t frames) {
  if (WiFi.status() != WL_CONNECTED) return;
  // Only fixed literals are passed as phase; no remote-controlled strings.
  static uint32_t seq = 0;
  char payload[220];
  const time_t clock = time(nullptr);
  const int n = snprintf(payload, sizeof(payload),
    "{\"v\":1,\"boot\":%lu,\"seq\":%lu,\"epoch\":%lld,"
    "\"uptime_ms\":%lu,\"event\":\"%s\",\"rule\":%u,\"slot\":%u,"
    "\"result\":%d,\"tx_ms\":%lu,\"frames\":%lu}",
    static_cast<unsigned long>(bootId()),
    static_cast<unsigned long>(++seq),
    static_cast<long long>(clock),
    static_cast<unsigned long>(millis()), phase,
    static_cast<unsigned>(rule), static_cast<unsigned>(slot), result,
    static_cast<unsigned long>(durationMs),
    static_cast<unsigned long>(frames));
  if (n <= 0 || static_cast<size_t>(n) >= sizeof(payload)) return;
  WiFiUDP udp;
  if (udp.beginPacket(PI_HOST, PORT)) {
    udp.write(reinterpret_cast<const uint8_t*>(payload), n);
    udp.endPacket();
  }
  udp.stop();
}
} // namespace pi_alarm_telemetry

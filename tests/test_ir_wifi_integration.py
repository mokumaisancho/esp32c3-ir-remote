"""Host regression tests for the exact compiled IR receive function and Wi-Fi/UI contracts.

These tests do not claim real ESP32 hardware or HTTP connectivity.
"""
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = (ROOT / "src/main.cpp").read_text(encoding="utf-8")
UI = (ROOT / "src/web_ui.h").read_text(encoding="utf-8")


def extract_body_function(source: str, marker: str) -> str:
    start = source.index(marker)
    brace = source.index("{", start)
    level = 0
    for offset in range(brace, len(source)):
        if source[offset] == "{":
            level += 1
        elif source[offset] == "}":
            level -= 1
            if level == 0:
                return source[start:offset + 1]
    raise AssertionError("unterminated firmware function")


class NetworkContracts(unittest.TestCase):
    def test_recovery_ap_persists_during_station_attempt(self):
        network = extract_body_function(SRC, "void startNetwork()")
        connect = extract_body_function(SRC, "bool connectStoredWifi()")
        self.assertIn("WiFi.mode(WIFI_AP_STA)", network)
        self.assertIn("WiFi.softAP(", network)
        self.assertLess(network.index("WiFi.softAP("), network.index("connectStoredWifi()"))
        self.assertNotIn("WIFI_STA)", connect)
        self.assertNotIn("WiFi.disconnect(true, true)", network)
        self.assertIn("WiFi.begin(ssid.c_str(), password.c_str())", connect)

    def test_live_addresses_and_rmt_flags_exposed_without_password(self):
        status = extract_body_function(SRC, "void handleStatus()")
        for key in ("sta_connected", "sta_ip", "sta_ssid", "setup_ap_ready", "setup_ap_ip",
                    "rmt_rx_ready", "rmt_tx_ready"):
            self.assertIn(f'\\\"{key}\\\"', status)
        self.assertIn("WiFi.status() == WL_CONNECTED", status)
        self.assertNotIn('prefs.getString("pass"', status)
        self.assertIn("rmtRxReady", extract_body_function(SRC, "void setupRmt()"))
        self.assertIn("rmtTxReady", extract_body_function(SRC, "void setupRmt()"))

    def test_user_interface_describes_both_networks_and_capture_health(self):
        self.assertIn("復旧用Wi-Fi", UI)
        self.assertIn("d.sta_ip", UI)
        self.assertIn("d.setup_ap_ip", UI)
        self.assertIn("d.rmt_rx_ready", UI)
        self.assertIn("実測 ", UI)
        self.assertIn("fetch(path,opt)", UI)


class CaptureBehavior(unittest.TestCase):
    @unittest.skipUnless(shutil.which("g++"), "g++ not installed")
    def test_real_receive_function_with_mocked_hal(self):
        # Compile the *actual* firmware learnSignal implementation, not an
        # independent rewrite, against a deterministic fake Arduino HAL.
        function = extract_body_function(SRC, "bool learnSignal(")
        harness = r"""
#include <cstdint>
#include <cstddef>
#include <vector>
#include <utility>
#include <cassert>
#include <iostream>
struct Signal { std::vector<int32_t> pulses; };
struct rmt_data_t { uint8_t level0; uint16_t duration0; uint8_t level1; uint16_t duration1; };
struct rmt_receive_config_t { uint32_t signal_range_min_ns; uint32_t signal_range_max_ns; };
using rmt_channel_handle_t = void*;
using QueueHandle_t = void*;
using esp_err_t = int;
constexpr int ESP_OK = 0;
constexpr int ESP_ERR_INVALID_STATE = 259;
constexpr int pdTRUE = 1;
namespace ircfg {
  constexpr size_t MAX_RMT_SYMBOLS=96;
  constexpr size_t MAX_PULSES=192;
  constexpr uint32_t LEARN_WINDOW_MS=5000;
  constexpr uint32_t RX_GLITCH_FILTER_US=80;
  constexpr uint32_t RX_IDLE_THRESHOLD_US=15000;
}
rmt_data_t rxSymbols[ircfg::MAX_RMT_SYMBOLS]{};
rmt_channel_handle_t rxChannel = reinterpret_cast<void*>(1);
QueueHandle_t rxDoneQueue = reinterpret_cast<void*>(2);
esp_err_t rxLastStartError = ESP_OK, rxLastResetError = ESP_OK;
uint32_t rxLastSymbolCount=0;
bool rmtRxReady = true;
uint32_t fake_time=0;
int scenario=0;
uint32_t millis() { return fake_time; }
void delay(uint32_t n) { fake_time += n; }
uint32_t pdMS_TO_TICKS(uint32_t ms) { return ms; }
int xQueueReset(QueueHandle_t q) { assert(q == rxDoneQueue); return pdTRUE; }
esp_err_t rmt_receive(rmt_channel_handle_t ch, void* data, size_t bytes, const rmt_receive_config_t* cfg) {
  assert(ch == rxChannel && data == rxSymbols && bytes == sizeof(rxSymbols));
  assert(cfg->signal_range_min_ns == 80000 && cfg->signal_range_max_ns == 15000000);
  return scenario == 0 ? ESP_ERR_INVALID_STATE : ESP_OK;
}
int xQueueReceive(QueueHandle_t q, size_t* count, uint32_t timeout) {
  assert(q == rxDoneQueue && timeout == 5000);
  if (scenario == 1) { *count=1; return pdTRUE; }
  if (scenario == 2) { *count=4; return pdTRUE; }
  fake_time += timeout;
  return 0;
}
esp_err_t rmt_disable(rmt_channel_handle_t ch) {
  assert(ch == rxChannel);
  return scenario == 4 ? ESP_ERR_INVALID_STATE : ESP_OK;
}
esp_err_t rmt_enable(rmt_channel_handle_t ch) { assert(ch == rxChannel); return ESP_OK; }
Signal normalizeReceived(const rmt_data_t*, size_t count) {
  Signal s;
  if (count >= 4) s.pulses={900,-450,900,-450,900,-450};
  else s.pulses={200,-200};
  return s;
}
"""
        harness += "\n" + function + "\n"
        harness += r"""
int main(){
  Signal s; uint32_t elapsed=0,attempts=0,early=0;
  scenario=0; fake_time=0; rmtRxReady=true;
  bool ok=learnSignal(s,elapsed,attempts,early);
  assert(!ok && elapsed<50 && attempts==1 && early==1 && rxLastStartError==ESP_ERR_INVALID_STATE);
  scenario=1; fake_time=0; rmtRxReady=true;
  ok=learnSignal(s,elapsed,attempts,early);
  assert(!ok && elapsed>=5000 && attempts>1 && early==0 && rxLastSymbolCount==1);
  scenario=2; fake_time=0; rmtRxReady=true;
  ok=learnSignal(s,elapsed,attempts,early);
  assert(ok && elapsed<50 && attempts==1 && s.pulses.size()==6);
  scenario=3; fake_time=0; rmtRxReady=true;
  ok=learnSignal(s,elapsed,attempts,early);
  assert(!ok && elapsed==5000 && attempts==1 && early==0 && rxLastResetError==ESP_OK && rmtRxReady);
  scenario=4; fake_time=0; rmtRxReady=true;
  ok=learnSignal(s,elapsed,attempts,early);
  assert(!ok && rxLastResetError==ESP_ERR_INVALID_STATE && !rmtRxReady);
  std::cout << "DIRECT_IDF_RECEIVE_5_SCENARIOS_PASS\n";
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            source = pathlib.Path(tmp) / "test_receive.cpp"
            binary = pathlib.Path(tmp) / "test_receive"
            source.write_text(harness, encoding="utf-8")
            build = subprocess.run(
                ["g++", "-std=c++17", "-O0", "-Wall", "-Wextra", "-Werror",
                 "-o", str(binary), str(source)],
                text=True, capture_output=True, timeout=60
            )
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            execute = subprocess.run([str(binary)], text=True, capture_output=True, timeout=15)
            self.assertEqual(execute.returncode, 0, execute.stdout + execute.stderr)
            self.assertIn("DIRECT_IDF_RECEIVE_5_SCENARIOS_PASS", execute.stdout)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_exact_web_ui_javascript_syntax(self):
        self.assertEqual(UI.count("<script>"), 1)
        script = UI.split("<script>", 1)[1].split("</script>", 1)[0]
        result = subprocess.run(["node", "--check", "-"], input=script,
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

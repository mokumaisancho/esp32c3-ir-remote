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
#include <vector>
#include <utility>
#include <cassert>
#include <iostream>
struct Signal { std::vector<int32_t> pulses; };
struct rmt_data_t { uint8_t level0; uint16_t duration0; uint8_t level1; uint16_t duration1; };
namespace ircfg {
  constexpr int IR_RX_PIN=5;
  constexpr size_t MAX_RMT_SYMBOLS=96;
  constexpr size_t MAX_PULSES=192;
  constexpr uint32_t LEARN_WINDOW_MS=5000;
}
uint32_t fake_time=0;
int scenario=0;
rmt_data_t rxSymbols[ircfg::MAX_RMT_SYMBOLS]{};
uint32_t millis() { return fake_time; }
void delay(uint32_t t) { fake_time += t; }
bool rmtRead(int pin, rmt_data_t*, size_t* count, uint32_t timeout) {
  assert(pin==5);
  if (scenario==0) return false;              // Immediate HAL failure
  if (scenario==1) { *count=1; return true; }   // A short/invalid noise burst
  if (scenario==2) { *count=4; return true; }   // Valid capture immediately
  fake_time += timeout;                        // Genuine 5000ms quiet timeout
  return false;
}
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
  Signal s;
  uint32_t elapsed=0,attempts=0,early=0;
  scenario=0; fake_time=0;
  bool ok=learnSignal(s,elapsed,attempts,early);
  assert(!ok && elapsed>=5000 && elapsed<5100 && attempts>=100 && early==attempts);
  scenario=1; fake_time=0;
  ok=learnSignal(s,elapsed,attempts,early);
  assert(!ok && elapsed>=5000 && elapsed<5100 && attempts>=100 && early==0);
  scenario=2; fake_time=0;
  ok=learnSignal(s,elapsed,attempts,early);
  assert(ok && elapsed<5000 && s.pulses.size()==6);
  scenario=3; fake_time=0;
  ok=learnSignal(s,elapsed,attempts,early);
  assert(!ok && elapsed>=5000 && attempts==1 && early==0);
  std::cout << "RECEIVE_TIMER_AND_VALID_SIGNAL_TEST_PASS\n";
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
            self.assertIn("RECEIVE_TIMER_AND_VALID_SIGNAL_TEST_PASS", execute.stdout)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_exact_web_ui_javascript_syntax(self):
        self.assertEqual(UI.count("<script>"), 1)
        script = UI.split("<script>", 1)[1].split("</script>", 1)[0]
        result = subprocess.run(["node", "--check", "-"], input=script,
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

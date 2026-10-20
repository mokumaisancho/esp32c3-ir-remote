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
    def test_wifimanager_owns_portal_and_ir_server_is_isolated(self):
        network = extract_body_function(SRC, "void startNetwork()")
        self.assertIn("wifiManager.autoConnect(", network)
        self.assertIn("wifiManager.setConfigPortalBlocking(false)", network)
        self.assertIn("wifiManager.setWiFiAutoReconnect(true)", network)
        self.assertIn("WebServer server(8080)", SRC)
        self.assertIn('MDNS.addService("http", "tcp", 8080)', network)
        self.assertNotIn("WiFi.softAP(", network)

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


class WifiProvisioningContracts(unittest.TestCase):
    def test_save_does_not_claim_association(self):
        save = extract_body_function(SRC, "void handleWifi()")
        self.assertIn('prefs.getString("ssid", "") == ssid', save)
        self.assertIn('prefs.getString("pass", "") == password', save)
        self.assertIn("WiFi.begin(ssid.c_str(), password.c_str())", save)
        self.assertIn('sendJson(202,', save)
        self.assertIn('\\\"connected\\\":false', save)
        self.assertNotIn("rebootAt = ", save)

    def test_status_reports_real_network_phase(self):
        status = extract_body_function(SRC, "void handleStatus()")
        for field in ("wifi_phase", "wifi_configured", "wifi_attempt_elapsed_ms", "sta_ip", "sta_status"):
            self.assertIn(field, status)
        for state in ("UNCONFIGURED", "SAVED", "CONNECTING", "CONNECTED", "FAILED"):
            self.assertIn(state, status)
        self.assertIn("WiFi.localIP() != IPAddress(0, 0, 0, 0)", status)

    def test_persistent_compact_two_column_signals_with_individual_delete(self):
        self.assertIn('LittleFS.begin(false)', SRC)
        self.assertIn('LittleFS.rename(tempPath, finalPath)', SRC)
        self.assertIn('loadSignalFromSlot(i, signal)', extract_body_function(SRC, "void handleSignals()"))
        self.assertIn('grid-template-columns:repeat(2,minmax(0,1fr))', UI)
        self.assertIn('el.append(name,send,del,meta)', UI)
        self.assertIn("del.onclick=async()=>", UI)
        self.assertNotIn('id="deleteSelected"', UI)
        self.assertNotIn('selectedIds', UI)

    def test_tx_carrier_polarity_is_not_reversed(self):
        tx = extract_body_function(SRC, "bool transmitFrame(")
        setup = extract_body_function(SRC, "void setupRmt()")
        self.assertIn("!ircfg::TX_ACTIVE_HIGH", tx)
        self.assertIn("!ircfg::TX_ACTIVE_HIGH", setup)
        self.assertIn("rmtWrite(ircfg::IR_TX_PIN", tx)

    def test_multiframe_replay_is_bounded_and_instrumented(self):
        tx = extract_body_function(SRC, "bool transmitSignal(")
        frame = extract_body_function(SRC, "bool transmitFrame(")
        learn = extract_body_function(SRC, "bool learnSignal(")
        self.assertIn("delayMicroseconds(gapUs % 1000U)", tx)
        self.assertIn("IR_TX_GAP", tx)
        self.assertIn("symbolCount, 200)", frame)
        self.assertIn("IR_RX_BEGIN", learn)
        self.assertIn("IR_RX_TIMEOUT", learn)

    def test_fast_trial_preserves_default_full_replay_and_tracks_latency(self):
        tx = extract_body_function(SRC, "bool transmitSignal(")
        saved = extract_body_function(SRC, "void handleSendSaved()")
        last = extract_body_function(SRC, "void handleSendLast()")
        self.assertIn("maxFrames = MAX_EXTRA_FRAMES + 1", tx)
        self.assertIn("std::min(signal.extraFrames.size(), maxFrames - 1)", tx)
        self.assertIn("lastTxFirstFrameMs", tx)
        self.assertIn("lastTxGapMs", tx)
        self.assertIn("lastTxFrameCount", tx)
        self.assertIn("transmitSignal(signal, maxFrames)", saved)
        self.assertIn("transmitSignal(lastSignal, maxFrames)", last)
        self.assertIn("const uint32_t loadMs = millis() - requestMs", saved)
        self.assertIn("id=\"txFastMode\"", UI)
        self.assertIn("max_frames:$('#txFastMode').checked?'1':'0'", UI)
        self.assertIn("result.tx_gap_wait_ms", UI)
        self.assertIn("result.tx_first_frame_ms", UI)

    def test_ui_polls_actual_status(self):
        self.assertIn("refreshStatus().catch(", UI)
        self.assertIn("},10000);", UI)
        self.assertIn("保存済み・接続試行中（成功未確認）", UI)
        self.assertNotIn("保存しました。ESP32-C3を再起動します。", UI)


class WifiEventTraceContracts(unittest.TestCase):
    def test_manager_starts_nonblocking_portal_and_exposes_result(self):
        fn = extract_body_function(SRC, "void startNetwork()")
        self.assertLess(fn.index("setConfigPortalBlocking(false)"), fn.index("wifiManager.autoConnect("))
        self.assertIn("event=WIFIMANAGER_READY", fn)
        self.assertIn("WiFi.status() == WL_CONNECTED", fn)

    def test_event_callback_reports_disconnection_reason_and_dhcp(self):
        fn = extract_body_function(SRC, "void onWifiEvent(")
        for event in ("STA_START", "STA_CONNECTED", "STA_DISCONNECTED",
                      "STA_GOT_IP", "STA_LOST_IP", "AP_START", "AP_STOP"):
            self.assertIn("event=" + event, fn)
        self.assertIn("info.wifi_sta_disconnected.reason", fn)
        self.assertIn("info.got_ip.ip_info.ip", fn)
        self.assertNotIn("password", fn)
        self.assertIn("WiFi.onEvent(onWifiEvent)", extract_body_function(SRC, "void startNetwork()"))

    def test_status_exposes_event_counters(self):
        fn = extract_body_function(SRC, "void handleStatus()")
        for field in ("wifi_last_disconnect_reason", "wifi_disconnect_count",
                      "wifi_association_count", "wifi_got_ip_count"):
            self.assertIn(field, fn)


class PersistenceAndRecoveryContracts(unittest.TestCase):
    def test_filesystem_preserves_existing_data_on_write_failure(self):
        save = extract_body_function(SRC, "bool saveSignalToSlot(")
        load = extract_body_function(SRC, "bool loadSignalFromSlot(")
        setup = extract_body_function(SRC, "void setup()")
        self.assertIn("fsReady = LittleFS.begin(false)", setup)
        self.assertNotIn("LittleFS.begin(true)", setup)
        self.assertIn("LittleFS.rename(finalPath, backupPath)", save)
        self.assertIn("LittleFS.rename(backupPath, finalPath)", save)
        self.assertIn("if (!LittleFS.exists(finalPath) && LittleFS.exists(backupPath))", load)

    def test_wifi_manager_processes_portal_without_blocking_ir(self):
        maintain = extract_body_function(SRC, "void maintainNetwork()")
        loop = extract_body_function(SRC, "void loop()")
        self.assertIn("wifiManager.process()", maintain)
        self.assertIn("server.handleClient()", loop)
        self.assertIn("maintainNetwork()", loop)
        self.assertNotIn("WiFi.disconnect(", maintain)
        self.assertNotIn("WiFi.begin(", maintain)


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
#include <string>
#include <utility>
#include <cassert>
#include <iostream>
struct Signal {
  std::vector<int32_t> pulses;
  std::vector<std::vector<int32_t>> extraFrames;
  std::vector<uint32_t> interFrameGapUs;
};
struct FakeServer {
  bool multi = false;
  bool hasArg(const char*) const { return multi; }
  std::string arg(const char*) const { return multi ? "1" : "0"; }
} server;
struct FakeSerial {
  template <typename... A> void printf(const char*, A...) const {}
} Serial;
constexpr size_t MAX_EXTRA_FRAMES = 127;
constexpr size_t MAX_CAPTURE_BYTES = 24U * 1024U;
struct FakeESP { size_t getFreeHeap() const { return 200000U; } } ESP;
bool captureTruncated = false;
uint32_t captureBytes = 0, captureBudget = 0;
uint32_t signalDurationUs(const Signal &s) {
  uint32_t n=0;for(int32_t p:s.pulses)n+=p<0?-p:p;return n;
}
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
  constexpr uint32_t RX_GLITCH_FILTER_US=1;
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
  assert(cfg->signal_range_min_ns == 1000 && cfg->signal_range_max_ns == 15000000);
  return scenario == 0 ? ESP_ERR_INVALID_STATE : ESP_OK;
}
int xQueueReceive(QueueHandle_t q, size_t* count, uint32_t timeout) {
  assert(q == rxDoneQueue && timeout > 0 && timeout <= 5000);
  if (scenario == 1) { *count=1; return pdTRUE; }
  if (scenario == 2) { *count=4; return pdTRUE; }
  if (scenario == 5) { *count=4; fake_time += 110; return pdTRUE; }
  if (scenario == 6) { *count=4; fake_time += 2; return pdTRUE; }
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
  scenario=5; fake_time=0; rmtRxReady=true; server.multi=true;
  ok=learnSignal(s,elapsed,attempts,early);
  assert(ok && s.extraFrames.size()>4 && s.extraFrames.size()==s.interFrameGapUs.size() && elapsed>=5000);
  server.multi=false;
  scenario=6; fake_time=0; rmtRxReady=true; server.multi=true;
  ok=learnSignal(s,elapsed,attempts,early);
  assert(!ok && captureTruncated && s.extraFrames.size()==MAX_EXTRA_FRAMES && elapsed<5000);
  server.multi=false;
  scenario=3; fake_time=0; rmtRxReady=true;
  ok=learnSignal(s,elapsed,attempts,early);
  assert(!ok && elapsed==5000 && attempts==1 && early==0 && rxLastResetError==ESP_OK && rmtRxReady);
  scenario=4; fake_time=0; rmtRxReady=true;
  ok=learnSignal(s,elapsed,attempts,early);
  assert(!ok && rxLastResetError==ESP_ERR_INVALID_STATE && !rmtRxReady);
  std::cout << "DIRECT_IDF_RECEIVE_7_SCENARIOS_PASS\n";
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
            self.assertIn("DIRECT_IDF_RECEIVE_7_SCENARIOS_PASS", execute.stdout)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_exact_web_ui_javascript_syntax(self):
        self.assertEqual(UI.count("<script>"), 1)
        script = UI.split("<script>", 1)[1].split("</script>", 1)[0]
        result = subprocess.run(["node", "--check", "-"], input=script,
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class LightingAlarmContracts(unittest.TestCase):
    def test_ntp_is_jst_and_no_automatic_execution_without_wifi(self):
        alarm = extract_body_function(SRC, "void runAlarmClock()")
        self.assertIn('configTzTime("JST-9"', alarm)
        self.assertIn('WiFi.status() == WL_CONNECTED', alarm)
        self.assertIn('if (!connected || !alarmsReady || !alarmClockValid()) return;', alarm)
        self.assertIn("alarm_policy::due(", alarm)
        self.assertIn("r.lastMinute = epochMinute", alarm)
        self.assertIn("persistAlarmRules()", alarm)
        self.assertLess(alarm.index("persistAlarmRules()"), alarm.index("transmitSignal(stored,"))
        self.assertIn("r.firstOnly ? 1 : MAX_EXTRA_FRAMES + 1", alarm)
        self.assertIn('setenv("TZ", "JST-9", 1)', SRC)

    def test_weekly_alarm_api_validates_saved_ir_and_never_formats_fs(self):
        register = extract_body_function(SRC, "void setupRoutes()")
        self.assertIn('"/api/alarms"', register)
        self.assertIn('"/api/alarms/save"', register)
        self.assertIn('"/api/alarms/delete"', register)
        save = extract_body_function(SRC, "void handleSaveAlarm()")
        self.assertIn("loadSignalFromSlot(slot, verifySignal)", save)
        self.assertIn("persistAlarmRules()", save)
        self.assertIn("alarmClockValid()", save)
        self.assertIn("LittleFS.begin(false)", SRC)
        delete = extract_body_function(SRC, "void handleDelete()")
        self.assertIn("照明アラームが参照中です", delete)

    def test_ui_offers_weekdays_clock_signal_and_rule_management(self):
        for term in ('照明アラーム', 'alarmTime', 'alarmWeekdays',
                     'alarmSignal', 'alarmFirstOnly', 'alarmEnabled',
                     'addAlarm', 'refreshAlarms()', 'id="alarmList"',
                     'dayText'):
            self.assertIn(term, UI)
        self.assertIn("'/api/alarms/save'", UI)
        self.assertIn("'/api/alarms/delete'", UI)
        self.assertIn("document.querySelectorAll('#alarmWeekdays input:checked')", UI)
        self.assertNotIn("登録したアラームはLittleFSに保存し", UI)
        self.assertNotIn("過ぎた時刻の後追い実行はしません", UI)
        self.assertNotIn('id="multi" type="checkbox"', UI)
        self.assertIn("form({multi:'1'", UI)


if __name__ == "__main__":
    unittest.main()

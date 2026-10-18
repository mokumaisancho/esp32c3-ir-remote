#include <Arduino.h>
#include <WiFi.h>
#include <WiFiManager.h>
#include <WebServer.h>

// Independent WiFiManager connectivity proof; the IR production code is untouched.
// Credentials are saved by WiFiManager via ESP32 Wi-Fi persistent storage.
WiFiManager manager;
WebServer checkServer(80);
uint32_t lastHeartbeat=0;

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("POC_WIFI_MANAGER_BOOT");
  manager.setDebugOutput(true);
  manager.setConnectTimeout(25);
  manager.setConfigPortalTimeout(0); // Remain available for configuration.
  // Deliberately uses an independent SSID to avoid confusing it with the old AP.
  Serial.println("POC_WIFI_MANAGER_CONNECTING");
  const bool ok=manager.autoConnect("ESP32C3-WIFI-POC","esp32poc35");
  Serial.printf("POC_WIFI_MANAGER_RESULT connected=%d status=%d ip=%s\n",
                ok,static_cast<int>(WiFi.status()),WiFi.localIP().toString().c_str());
  if (!ok) {
    Serial.println("POC_WIFI_MANAGER_TIMEOUT");
    return;
  }
  checkServer.on("/", HTTP_GET, []() {
    checkServer.send(200,"text/plain",
      String("ESP32C3_WIFI_POC_OK ip=")+WiFi.localIP().toString()+"\n");
  });
  checkServer.on("/status", HTTP_GET, []() {
    checkServer.send(200,"application/json",
      String("{\"connected\":")+(WiFi.status()==WL_CONNECTED?"true":"false")+
      ",\"ip\":\""+WiFi.localIP().toString()+"\"}");
  });
  checkServer.begin();
  Serial.println("POC_HTTP_READY");
}
void loop() {
  checkServer.handleClient();
  if (millis()-lastHeartbeat>=5000) {
    lastHeartbeat=millis();
    Serial.printf("POC_HEARTBEAT status=%d ip=%s\n",
       static_cast<int>(WiFi.status()),WiFi.localIP().toString().c_str());
  }
  delay(10);
}

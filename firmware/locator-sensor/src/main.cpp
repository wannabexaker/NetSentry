// NetSentry locator sensor — an ESP32 that reports how strongly it hears each
// WiFi device, so NetSentry can work out where devices are (`/where`).
//
// How it works
//   The board joins your WiFi like any other device and stays on that access
//   point's channel. While connected it also listens to every frame on the
//   channel ("promiscuous mode") and remembers, per sender, how strong the
//   signal was. NetSentry asks for that table over HTTP:
//
//     GET /rssi[?k=<key>]  ->
//       {"id":"s1","mac":"aabbccddeeff","fw":1,"up":1234,"ch":6,
//        "seen":[["a0b1c2d3e4f5",-61,12,3], ...]}      (mac, dBm, frames, age s)
//
// What it cannot do
//   One 2.4 GHz radio, parked on one channel: devices on 5 GHz, or on another
//   2.4 GHz channel, are not heard. It stores nothing and sends nothing by
//   itself; it only answers when asked.
//
// Settings live in include/config.h (copy config.example.h; it is git-ignored).

#include <Arduino.h>
#include <WebServer.h>
#include <WiFi.h>
#include <esp_wifi.h>

#if __has_include("config.h")
#include "config.h"
#else
#error "Copy include/config.example.h to include/config.h and fill it in."
#endif

static const int FIRMWARE = 1;
static const int TABLE_SIZE = 96;            // senders remembered at once
static const uint32_t MAX_AGE_S = 90;        // older than this is not reported
static const uint32_t OFFLINE_RESTART_MS = 120000;

struct Entry {
  uint8_t mac[6];
  int16_t rssi_x16;                          // smoothed dBm, fixed point (x16)
  uint16_t frames;                           // frames since the last report
  uint32_t last_ms;
  bool used;
};

static Entry table[TABLE_SIZE];
static Entry snapshot[TABLE_SIZE];
static portMUX_TYPE table_lock = portMUX_INITIALIZER_UNLOCKED;
static WebServer server(80);
static uint32_t offline_since_ms = 0;

// Called by the WiFi driver for every frame heard. Keep it short.
static void on_frame(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
  if (pkt->rx_ctrl.sig_len < 24) return;     // too short to carry a sender
  const uint8_t *sender = pkt->payload + 10; // 802.11 address 2 = transmitter
  if (sender[0] & 0x01) return;              // group address: nobody's own
  const int16_t rssi_x16 = (int16_t)(pkt->rx_ctrl.rssi * 16);
  const uint32_t now = millis();

  portENTER_CRITICAL(&table_lock);
  int slot = -1, oldest = 0;
  for (int i = 0; i < TABLE_SIZE; i++) {
    if (table[i].used && memcmp(table[i].mac, sender, 6) == 0) { slot = i; break; }
    if (!table[i].used) { if (slot < 0) slot = i; continue; }
    if (table[i].last_ms < table[oldest].last_ms || !table[oldest].used) oldest = i;
  }
  if (slot < 0) slot = oldest;               // table full: forget the stalest
  Entry &e = table[slot];
  if (!e.used || memcmp(e.mac, sender, 6) != 0) {
    memcpy(e.mac, sender, 6);
    e.rssi_x16 = rssi_x16;
    e.frames = 0;
    e.used = true;
  } else {
    e.rssi_x16 += (rssi_x16 - e.rssi_x16) / 4;   // moving average
  }
  if (e.frames < 65535) e.frames++;
  e.last_ms = now;
  portEXIT_CRITICAL(&table_lock);
}

static bool key_ok() {
  return strlen(SENSOR_KEY) == 0 || server.arg("k") == SENSOR_KEY;
}

static void handle_rssi() {
  if (!key_ok()) { server.send(403, "text/plain", "wrong key\n"); return; }

  const uint32_t now = millis();
  portENTER_CRITICAL(&table_lock);
  memcpy(snapshot, table, sizeof(table));
  for (int i = 0; i < TABLE_SIZE; i++) table[i].frames = 0;
  portEXIT_CRITICAL(&table_lock);

  uint8_t own[6];
  WiFi.macAddress(own);
  char line[160];
  snprintf(line, sizeof(line),
           "{\"id\":\"%s\",\"mac\":\"%02x%02x%02x%02x%02x%02x\",\"fw\":%d,"
           "\"up\":%lu,\"ch\":%d,\"seen\":[",
           SENSOR_ID, own[0], own[1], own[2], own[3], own[4], own[5], FIRMWARE,
           (unsigned long)(now / 1000), (int)WiFi.channel());
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "application/json", "");
  server.sendContent(line);

  bool first = true;
  for (int i = 0; i < TABLE_SIZE; i++) {
    const Entry &e = snapshot[i];
    if (!e.used) continue;
    const uint32_t age_s = (now - e.last_ms) / 1000;
    if (age_s > MAX_AGE_S) continue;
    snprintf(line, sizeof(line), "%s[\"%02x%02x%02x%02x%02x%02x\",%d,%u,%lu]",
             first ? "" : ",", e.mac[0], e.mac[1], e.mac[2], e.mac[3], e.mac[4],
             e.mac[5], (int)(e.rssi_x16 / 16), (unsigned)e.frames, (unsigned long)age_s);
    server.sendContent(line);
    first = false;
  }
  server.sendContent("]}");
  server.sendContent("");                    // end of chunked body
}

static void handle_root() {
  char text[200];
  snprintf(text, sizeof(text),
           "NetSentry locator sensor \"%s\" (firmware %d)\nchannel %d, signal %d dBm, up %lu s\n"
           "NetSentry reads /rssi\n",
           SENSOR_ID, FIRMWARE, (int)WiFi.channel(), (int)WiFi.RSSI(),
           (unsigned long)(millis() / 1000));
  server.send(200, "text/plain", text);
}

static void start_listening() {
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&on_frame);
  esp_wifi_set_promiscuous(true);
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);                      // power save would miss frames
  WiFi.setAutoReconnect(true);
#ifdef STATIC_IP
  WiFi.config(IPAddress(STATIC_IP), IPAddress(STATIC_GATEWAY), IPAddress(STATIC_MASK),
              IPAddress(STATIC_GATEWAY));
#endif
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.printf("\nNetSentry locator sensor %s: joining %s", SENSOR_ID, WIFI_SSID);
  for (int i = 0; i < 120 && WiFi.status() != WL_CONNECTED; i++) {
    delay(500);
    Serial.print(".");
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println(" no luck, restarting");
    delay(1000);
    ESP.restart();
  }
  Serial.printf(" ok\naddress %s, channel %d\n", WiFi.localIP().toString().c_str(),
                (int)WiFi.channel());
  start_listening();
  server.on("/", handle_root);
  server.on("/rssi", handle_rssi);
  server.begin();
}

void loop() {
  server.handleClient();
  if (WiFi.status() == WL_CONNECTED) {
    offline_since_ms = 0;
  } else if (offline_since_ms == 0) {
    offline_since_ms = millis() | 1;
  } else if (millis() - offline_since_ms > OFFLINE_RESTART_MS) {
    ESP.restart();                           // lost for two minutes: start clean
  }
  delay(2);
}

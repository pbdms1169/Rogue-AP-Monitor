/*
  Portable Rogue AP Monitor & Honeypot Detector  -  ESP32 edition
  ----------------------------------------------------------------
  Hardware : ESP32 DevKit + 0.96" I2C OLED (SSD1306) + LED + active buzzer
  Libraries: Adafruit SSD1306, Adafruit GFX  (Library Manager)
  Board    : "ESP32 Dev Module"

  The device only SCANS (passive listening for beacons). It never connects to,
  deauthenticates or attacks any network. Use only where you are authorised.

  Detections
    EVIL TWIN   - unknown BSSID using one of your SSIDs
    DOWNGRADE   - your AP/SSID offered with weaker security
    CH MISMATCH - your BSSID seen on an unexpected SSID (spoof)
    HONEYPOT    - one BSSID advertising many SSIDs
    OPEN LURE   - open network with a popular hotspot name
*/

#include <WiFi.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "config.h"

#define SCREEN_W 128
#define SCREEN_H 64
Adafruit_SSD1306 oled(SCREEN_W, SCREEN_H, &Wire, -1);

enum Sev { SEV_NONE = 0, SEV_MEDIUM = 1, SEV_HIGH = 2, SEV_CRIT = 3 };

struct Alert {
  Sev sev;
  String title;   // short, fits one OLED line (max ~21 chars)
  String detail;  // second line
  String detail2; // third line
};

const int MAX_ALERTS = 10;
const int MAX_APS = 40;

Alert alerts[MAX_ALERTS];
int alertCount = 0;
int apCount = 0;
Sev worst = SEV_NONE;

// scan cache for multi-SSID detection
String cacheBssid[MAX_APS];
String cacheSsid[MAX_APS];

unsigned long lastScan = 0;
unsigned long lastPage = 0;
unsigned long muteUntil = 0;
int page = 0;
unsigned long scans = 0;

// ---------------------------------------------------------------- helpers
int encRank(wifi_auth_mode_t m) {
  switch (m) {
    case WIFI_AUTH_OPEN:            return 0;
    case WIFI_AUTH_WEP:             return 1;
    case WIFI_AUTH_WPA_PSK:         return 2;
    case WIFI_AUTH_WPA2_PSK:
    case WIFI_AUTH_WPA_WPA2_PSK:
    case WIFI_AUTH_WPA2_ENTERPRISE: return 3;
    case WIFI_AUTH_WPA3_PSK:
    case WIFI_AUTH_WPA2_WPA3_PSK:   return 4;
    default:                        return 3;
  }
}

const char* encName(int r) {
  static const char* n[] = { "OPEN", "WEP", "WPA", "WPA2", "WPA3" };
  return n[constrain(r, 0, 4)];
}

void addAlert(Sev s, const String& t, const String& d1, const String& d2 = "") {
  if (alertCount >= MAX_ALERTS) return;
  alerts[alertCount++] = { s, t, d1, d2 };
  if (s > worst) worst = s;
  Serial.printf("[%s] %s | %s | %s\n",
                s == SEV_CRIT ? "CRITICAL" : s == SEV_HIGH ? "HIGH" : "MEDIUM",
                t.c_str(), d1.c_str(), d2.c_str());
}

const TrustedAP* trustedByBssid(const String& b) {
  for (int i = 0; i < TRUSTED_COUNT; i++)
    for (int j = 0; j < 4; j++)
      if (strlen(TRUSTED[i].bssid[j]) && b.equalsIgnoreCase(TRUSTED[i].bssid[j]))
        return &TRUSTED[i];
  return nullptr;
}

bool isProtectedSsid(const String& s) {
  if (s.length() == 0) return false;
  for (int i = 0; i < TRUSTED_COUNT; i++)
    if (s.equals(TRUSTED[i].ssid)) return true;
  for (int i = 0; i < PROTECTED_EXTRA_COUNT; i++)
    if (strlen(PROTECTED_EXTRA[i]) && s.equals(PROTECTED_EXTRA[i])) return true;
  return false;
}

const TrustedAP* trustedBySsid(const String& s) {
  for (int i = 0; i < TRUSTED_COUNT; i++)
    if (s.equals(TRUSTED[i].ssid)) return &TRUSTED[i];
  return nullptr;
}

bool isHotspotName(const String& s) {
  String l = s;
  l.toLowerCase();
  for (int i = 0; i < HOTSPOT_COUNT; i++)
    if (l == HOTSPOT_NAMES[i]) return true;
  return false;
}

String shortMac(const String& m) { return m.substring(9); }  // last 3 octets

// ---------------------------------------------------------------- detection
void runDetection() {
  alertCount = 0;
  worst = SEV_NONE;

  for (int i = 0; i < apCount; i++) {
    String ssid  = cacheSsid[i];
    String bssid = cacheBssid[i];
    int rssi     = WiFi.RSSI(i);
    int ch       = WiFi.channel(i);
    int rank     = encRank((wifi_auth_mode_t)WiFi.encryptionType(i));

    const TrustedAP* tb = trustedByBssid(bssid);

    // 1) trusted BSSID whose parameters changed
    if (tb) {
      if (ssid.length() && !ssid.equals(tb->ssid)) {
        addAlert(SEV_CRIT, "BSSID SPOOF",
                 "Trusted MAC " + shortMac(bssid), "now SSID: " + ssid);
      } else if (rank < tb->minEnc) {
        addAlert(SEV_CRIT, "DOWNGRADE!",
                 String(tb->ssid) + " is " + encName(rank),
                 "expected " + String(encName(tb->minEnc)));
      }
      continue;
    }

    // 2) evil twin: protected SSID from an unknown BSSID
    if (isProtectedSsid(ssid)) {
      const TrustedAP* net = trustedBySsid(ssid);
      Sev s = SEV_HIGH;
      String extra = String("ch") + ch + " " + encName(rank) + " " + rssi + "dBm";
      if (net && rank < net->minEnc) s = SEV_CRIT;      // open clone of secured net
      if (rssi > STRONG_RSSI) s = SEV_CRIT;             // physically very close
      addAlert(s, "EVIL TWIN: " + ssid, "Unknown " + shortMac(bssid), extra);
      continue;
    }

    // 3) open network with a commonly spoofed hotspot name
    if (rank == 0 && ssid.length() && isHotspotName(ssid)) {
      addAlert(SEV_MEDIUM, "OPEN LURE", ssid,
               String("ch") + ch + " " + rssi + "dBm");
    }
  }

  // 4) honeypot: one BSSID advertising many SSIDs
  for (int i = 0; i < apCount; i++) {
    // process each BSSID only at its first occurrence
    bool seen = false;
    for (int k = 0; k < i; k++)
      if (cacheBssid[k] == cacheBssid[i]) { seen = true; break; }
    if (seen) continue;

    int distinct = 0;
    String names[MAX_APS];
    for (int j = i; j < apCount; j++) {
      if (cacheBssid[j] != cacheBssid[i]) continue;
      bool dup = false;
      for (int d = 0; d < distinct; d++)
        if (names[d] == cacheSsid[j]) { dup = true; break; }
      if (!dup) names[distinct++] = cacheSsid[j];
    }
    if (distinct >= MULTI_SSID_LIMIT) {
      addAlert(SEV_HIGH, "HONEYPOT/KARMA",
               shortMac(cacheBssid[i]) + " has " + distinct + " SSIDs",
               names[0] + "," + names[1]);
    }
  }
}

// ---------------------------------------------------------------- scanning
void doScan() {
  drawStatus("Scanning...");
  int n = WiFi.scanNetworks(false, true);   // blocking, include hidden
  apCount = 0;
  if (n > 0) {
    for (int i = 0; i < n && apCount < MAX_APS; i++) {
      cacheBssid[apCount] = WiFi.BSSIDstr(i);
      cacheSsid[apCount]  = WiFi.SSID(i);
      // keep the index aligned with WiFi.xxx(i) calls in runDetection
      apCount++;
    }
  }
  runDetection();
  scans++;
  page = 0;
  lastPage = millis();
  Serial.printf("Scan #%lu: %d APs, %d alerts\n", scans, apCount, alertCount);
  // NOTE: scan results stay valid in WiFi.* until WiFi.scanDelete()
}

// ---------------------------------------------------------------- display
void drawStatus(const char* msg) {
  oled.clearDisplay();
  oled.setTextSize(1);
  oled.setTextColor(SSD1306_WHITE);
  oled.setCursor(0, 0);
  oled.println("ROGUE AP MONITOR");
  oled.drawLine(0, 10, 127, 10, SSD1306_WHITE);
  oled.setCursor(0, 28);
  oled.println(msg);
  oled.display();
}

void drawScreen() {
  oled.clearDisplay();
  oled.setTextSize(1);
  oled.setTextColor(SSD1306_WHITE);

  // header
  oled.setCursor(0, 0);
  oled.printf("AP:%d  Scan:%lu", apCount, scans);
  if (millis() < muteUntil) oled.print(" MUTE");
  oled.drawLine(0, 10, 127, 10, SSD1306_WHITE);

  if (alertCount == 0) {
    oled.setTextSize(2);
    oled.setCursor(18, 24);
    oled.println("ALL OK");
    oled.setTextSize(1);
    oled.setCursor(10, 50);
    oled.println("No rogue APs found");
  } else {
    Alert& a = alerts[page % alertCount];
    oled.setCursor(0, 14);
    oled.printf("[%d/%d] %s", (page % alertCount) + 1, alertCount,
                a.sev == SEV_CRIT ? "CRITICAL" : a.sev == SEV_HIGH ? "HIGH" : "MEDIUM");
    oled.setCursor(0, 26);
    oled.println(a.title.substring(0, 21));
    oled.setCursor(0, 38);
    oled.println(a.detail.substring(0, 21));
    oled.setCursor(0, 50);
    oled.println(a.detail2.substring(0, 21));
  }
  oled.display();
}

// ---------------------------------------------------------------- LED + buzzer
void updateOutputs() {
  unsigned long t = millis();
  bool muted = t < muteUntil;
  bool led = false, buz = false;

  switch (worst) {
    case SEV_CRIT:  led = (t / 120) % 2;                 // fast blink
                    buz = !muted && (((t % 1000) < 150) || (((t % 1000) > 300) && ((t % 1000) < 450)));
                    break;                                 // double beep each second
    case SEV_HIGH:  led = (t / 300) % 2;                 // medium blink
                    buz = !muted && ((t % 2000) < 200);
                    break;
    case SEV_MEDIUM: led = true;                          // steady on
                    break;
    default:        led = ((t % 3000) < 40);              // tiny heartbeat flash
  }
  digitalWrite(LED_PIN, led);
  digitalWrite(BUZZER_PIN, buz);
}

// ---------------------------------------------------------------- setup/loop
void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(MUTE_BTN_PIN, INPUT_PULLUP);

  Wire.begin(OLED_SDA, OLED_SCL);
  if (!oled.begin(SSD1306_SWITCHCAPVCC, OLED_ADDR)) {
    Serial.println("OLED not found! Check wiring / address.");
    for (;;) { digitalWrite(LED_PIN, !digitalRead(LED_PIN)); delay(150); }
  }

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  // power-on self test: LED + short beep
  drawStatus("Self test...");
  digitalWrite(LED_PIN, HIGH);
  digitalWrite(BUZZER_PIN, HIGH);
  delay(200);
  digitalWrite(BUZZER_PIN, LOW);
  digitalWrite(LED_PIN, LOW);
  delay(300);

  doScan();
  lastScan = millis();
}

void loop() {
  unsigned long t = millis();

  if (digitalRead(MUTE_BTN_PIN) == LOW) {        // BOOT button
    muteUntil = t + MUTE_TIME_MS;
    delay(200);
  }

  if (t - lastScan >= SCAN_INTERVAL_MS) {
    doScan();
    lastScan = millis();
  }

  if (t - lastPage >= 2500) {                    // rotate through alerts
    page++;
    lastPage = t;
  }

  drawScreen();
  updateOutputs();
  delay(20);
}

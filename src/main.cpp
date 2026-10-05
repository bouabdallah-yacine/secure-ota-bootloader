/*
 * ============================================================================
 *  Secure bootloader with signed updates (ESP32, simulated on Wokwi)
 * ============================================================================
 *  At boot, the BOOTLOADER selects the slot to run and verifies its ECDSA P-256
 *  signature (mbedTLS). Then the APPLICATION starts: it blinks the LED at the
 *  rate stored in its image and offers updates.
 *
 *  Menu (serial monitor):
 *    1  install v2.0                       (signed, valid)
 *    2  install v3.0                       (signed but buggy → automatic rollback)
 *    3  install a tampered image           (modified content)
 *    4  install an image signed with another key
 *    5  downgrade to v1.0                  (old version → rejected)
 *    6  power cut while installing v2.0
 *    s  slot status    r  reboot    e  factory reset
 *
 *  Web dashboard served by the ESP32: http://localhost:8183 (Wokwi port forwarding).
 *
 *  The core (bootloader.c, sha256.c) is portable C, tested on a PC with
 *  simulated power cuts at every flash write (test/).
 *
 *  Note: in the simulator, the ESP32 cannot execute downloaded code.
 *  The image therefore carries the application configuration (blink rate,
 *  message, self-test). On a real board, the bootloader would jump to the slot
 *  address, like MCUboot. All the security logic is identical.
 * ============================================================================
 */
#include <Arduino.h>
#include <stdarg.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include "esp_partition.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "bootloader.h"
#include "public_key.h"
#include "demo_images.h"
#include "web_page.h"

#define PIN_LED_APP  2     // green LED: application blink
#define PIN_LED_SEC  4     // red LED: image rejected

Adafruit_SSD1306 oled(128, 64, &Wire, -1);
const esp_partition_t *part = nullptr;

// ---------------------------------------------------------------------------
//  Platform: real ESP32 flash (data partition) + mbedTLS
// ---------------------------------------------------------------------------
static int fRead(void *, uint32_t off, void *buf, uint32_t n)        { return esp_partition_read(part, off, buf, n) == ESP_OK ? 0 : -1; }
static int fWrite(void *, uint32_t off, const void *buf, uint32_t n) { return esp_partition_write(part, off, buf, n) == ESP_OK ? 0 : -1; }
static int fErase(void *, uint32_t off, uint32_t n)                  { return esp_partition_erase_range(part, off, n) == ESP_OK ? 0 : -1; }
static bl_flash_t flashDev = { fRead, fWrite, fErase, nullptr };

static int verifyMbedtls(const uint8_t pub[65], const uint8_t hash[32], const uint8_t sig[64]) {
  mbedtls_ecp_group grp; mbedtls_ecp_point q; mbedtls_mpi r, s;
  mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&q); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
  int ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
           mbedtls_ecp_point_read_binary(&grp, &q, pub, 65) == 0 &&
           mbedtls_mpi_read_binary(&r, sig, 32) == 0 &&
           mbedtls_mpi_read_binary(&s, sig + 32, 32) == 0 &&
           mbedtls_ecdsa_verify(&grp, hash, 32, &q, &r, &s) == 0;
  mbedtls_mpi_free(&r); mbedtls_mpi_free(&s); mbedtls_ecp_point_free(&q); mbedtls_ecp_group_free(&grp);
  return ok;
}

bl_t bl;
bl_decision_t boot;

// Application configuration read from the booted image
struct AppCfg { char name[20]; int blink; bool selftestOk; char msg[32]; } app;

static void parseDescriptor(int slot) {
  char d[128] = {0};
  fRead(nullptr, bl_slot_addr(slot) + FW_HDR_SIZE, d, sizeof d - 1);
  strcpy(app.name, "?"); app.blink = 500; app.selftestOk = true; strcpy(app.msg, "");
  for (char *tok = strtok(d, ";"); tok; tok = strtok(nullptr, ";")) {
    if (!strncmp(tok, "name=", 5)) strlcpy(app.name, tok + 5, sizeof app.name);
    else if (!strncmp(tok, "blink=", 6)) app.blink = atoi(tok + 6);
    else if (!strncmp(tok, "selftest=", 9)) app.selftestOk = !strcmp(tok + 9, "ok");
    else if (!strncmp(tok, "msg=", 4)) strlcpy(app.msg, tok + 4, sizeof app.msg);
  }
}

static String ver(uint32_t v) { return String(v >> 16) + "." + String((v >> 8) & 0xFF) + "." + String(v & 0xFF); }

// ---------------------------------------------------------------------------
//  Display
// ---------------------------------------------------------------------------
volatile const char *g_status = "";
volatile int g_progress = -1;
volatile bool g_busy = false;              // update in progress
uint32_t g_verifyMs = 0;                   // verification time at boot

// Log: every message goes to the serial monitor AND to the web page
#define LOG_LINES 16
struct LogLine { uint32_t t; char m[92]; };
LogLine logBuf[LOG_LINES]; volatile uint32_t logCount = 0;
portMUX_TYPE logMux = portMUX_INITIALIZER_UNLOCKED;
static void logStore(const char *m) {
  while (*m == '\n' || *m == ' ') m++;                      // leading spaces and newlines
  if (!*m) return;
  LogLine l; l.t = millis(); strlcpy(l.m, m, sizeof l.m);
  size_t n = strlen(l.m); while (n && (l.m[n - 1] == '\n' || l.m[n - 1] == ' ')) l.m[--n] = 0;
  for (char *c = l.m; *c; c++) if (*c == '"' || *c == '\\') *c = '\'';   // JSON-safe
  portENTER_CRITICAL(&logMux); logBuf[logCount % LOG_LINES] = l; logCount++; portEXIT_CRITICAL(&logMux);
}
static void LOG(const char *fmt, ...) {
  char b[160]; va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
  Serial.print(b); logStore(b);
}
static void LOGLN(const char *m) { Serial.println(m); logStore(m); }

// Slot summary for the web page (recomputed by refreshSlots)
struct SlotInfo { char name[16]; uint32_t ver; int status; bool active, pending; };
SlotInfo slotInfo[2];

// Slot summary, recomputed only when it changes (verification costs CPU time)
char slotTxt[2][24];
static void slotLine(int slot, char *out, size_t n) {
  fw_header_t h;
  img_status_t s = bl_verify_slot(&bl, slot, &h);
  if (s == IMG_OK) snprintf(out, n, "%c: %s%s", 'A' + slot, h.name, slot == bl.st.active ? " *" : "");
  else snprintf(out, n, "%c: %s", 'A' + slot, s == IMG_ERR_EMPTY ? "empty" : "INVALID");
}

static void refreshSlots() {
  slotLine(0, slotTxt[0], sizeof slotTxt[0]); slotLine(1, slotTxt[1], sizeof slotTxt[1]);
  for (int i = 0; i < 2; i++) {
    fw_header_t h; img_status_t st = bl_verify_slot(&bl, i, &h);
    SlotInfo si = {}; si.status = st;
    if (st == IMG_OK) { strlcpy(si.name, h.name, sizeof si.name); si.ver = h.fw_version; }
    si.active = (i == bl.st.active); si.pending = (i == bl.st.pending);
    slotInfo[i] = si;
  }
}

void taskDisplay(void *) {
  for (;;) {
    const char *a = slotTxt[0], *b = slotTxt[1];
    oled.clearDisplay(); oled.setTextColor(SSD1306_WHITE); oled.setTextSize(1);
    oled.setCursor(0, 0);  oled.printf("APP %s", app.name);
    oled.setCursor(0, 10); oled.printf("%s", boot.trial ? "TRIAL BOOT" : "confirmed version");
    oled.drawLine(0, 20, 127, 20, SSD1306_WHITE);
    oled.setCursor(0, 24); oled.print(a);
    oled.setCursor(0, 34); oled.print(b);
    oled.setCursor(0, 46);
    if (g_progress >= 0) {
      oled.drawRect(0, 46, 128, 8, SSD1306_WHITE);
      oled.fillRect(2, 48, (124 * g_progress) / 100, 4, SSD1306_WHITE);
    }
    oled.setCursor(0, 56); oled.print((const char *)g_status);
    oled.display();
    vTaskDelay(pdMS_TO_TICKS(150));
  }
}

// ---------------------------------------------------------------------------
//  Application
// ---------------------------------------------------------------------------
void taskBlink(void *) {
  for (;;) { digitalWrite(PIN_LED_APP, !digitalRead(PIN_LED_APP)); vTaskDelay(pdMS_TO_TICKS(app.blink)); }
}

static void printSlots() {
  for (int s = 0; s < 2; s++) {
    fw_header_t h;
    img_status_t st = bl_verify_slot(&bl, s, &h);
    Serial.printf("  slot %c : ", 'A' + s);
    if (st == IMG_OK) Serial.printf("%-12s v%s  signature OK%s\n", h.name, ver(h.fw_version).c_str(),
                                    s == bl.st.active ? "  <- active" : (s == bl.st.pending ? "  <- on trial" : ""));
    else Serial.printf("%s\n", img_status_str(st));
  }
  Serial.printf("  minimum allowed version (anti-rollback): v%s\n", ver(bl.st.min_version).c_str());
}

static void rejectFlash() {
  for (int i = 0; i < 6; i++) { digitalWrite(PIN_LED_SEC, i % 2 == 0); delay(150); }
}

static void installImage(const uint8_t *img, uint32_t n, const char *what, bool powerCut) {
  LOG("\n>>> Downloading: %s (%lu bytes) into slot %c\n", what, (unsigned long)n, 'A' + bl_inactive_slot(&bl));
  g_status = "downloading...";
  g_busy = true;
  if (bl_update_begin(&bl, n)) { LOGLN("    flash ERROR"); return; }
  for (uint32_t off = 0; off < n; off += 256) {
    uint32_t k = n - off < 256 ? n - off : 256;
    bl_update_write(&bl, off, img + off, k);
    g_progress = (int)((off + k) * 100 / n);
    if (powerCut && off > n / 2) {
      LOGLN("    !!! POWER CUT at 50% of the write !!!");
      Serial.flush();
      delay(300);
      esp_restart();                                   // just like a real power cut
    }
    vTaskDelay(pdMS_TO_TICKS(15));
  }
  g_progress = -1;
  LOGLN("    Verifying: payload SHA-256, ECDSA P-256 signature, version...");
  uint32_t t0 = micros();
  fw_header_t h;
  img_status_t s = bl_update_finish(&bl, &h);
  uint32_t us = micros() - t0;
  if (s == IMG_OK) {
    LOG("    ACCEPTED (%lu ms): %s v%s. Rebooting to install it...\n", (unsigned long)(us / 1000), h.name, ver(h.fw_version).c_str());
    g_status = "OK -> rebooting";
    delay(1500);
    esp_restart();
  } else {
    refreshSlots();
    LOG("    REJECTED: %s\n", img_status_str(s));
    LOGLN("    The current firmware keeps running, nothing was installed.");
    g_status = "IMAGE REJECTED";
    g_busy = false;
    rejectFlash();
  }
}

static void menu() {
  Serial.println("\nMenu: 1 valid v2.0 | 2 buggy v3.0 | 3 tampered image | 4 other key | 5 downgrade to v1.0");
  Serial.println("      6 power cut | s status | r reboot | e factory reset");
}

QueueHandle_t webCmdQ;                     // commands sent by the web page

void taskApp(void *) {
  // Self-test of the new version (trial boot)
  if (boot.trial) {
    LOG("[APP] Trial boot %d/%d: running self-test...\n", bl.st.tries, BL_MAX_TRIES);
    g_status = "self-test...";
    vTaskDelay(pdMS_TO_TICKS(2500));
    if (app.selftestOk) {
      bl_confirm(&bl);
      boot.trial = 0;
      refreshSlots();
      LOG("[APP] Self-test OK: version confirmed. Minimum version = v%s\n", ver(bl.st.min_version).c_str());
      g_status = "self-test OK";
    } else {
      LOGLN("[APP] Self-test FAILED: the application crashes -> the watchdog reboots the board");
      g_status = "CRASH!";
      vTaskDelay(pdMS_TO_TICKS(2000));
      esp_restart();
    }
  }
  menu();
  for (;;) {
    char c = 0;
    if (Serial.available()) c = Serial.read();
    else if (xQueueReceive(webCmdQ, &c, 0) != pdTRUE) c = 0;
    if (c) {
      switch (c) {
        case '1': installImage(IMG_V2, sizeof IMG_V2, "v2.0 (signed)", false); break;
        case '2': installImage(IMG_V3_BUGGY, sizeof IMG_V3_BUGGY, "v3.0 (signed, buggy)", false); break;
        case '3': installImage(IMG_HACKED, sizeof IMG_HACKED, "tampered image (content + hash modified)", false); break;
        case '4': installImage(IMG_WRONG_KEY, sizeof IMG_WRONG_KEY, "image signed with another key", false); break;
        case '5': installImage(IMG_DOWNGRADE, sizeof IMG_DOWNGRADE, "old version v1.0", false); break;
        case '6': installImage(IMG_V2, sizeof IMG_V2, "v2.0 (with power cut)", true); break;
        case 's': printSlots(); break;
        case 'r': LOGLN("Rebooting..."); delay(200); esp_restart(); break;
        case 'e':
          LOGLN("Factory reset: erasing everything...");
          fErase(nullptr, 0, BL_FLASH_SIZE); delay(200); esp_restart(); break;
        default: continue;
      }
      menu();
    }
    vTaskDelay(pdMS_TO_TICKS(50));
  }
}

// ---------------------------------------------------------------------------
//  BOOTLOADER
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
//  Web dashboard
// ---------------------------------------------------------------------------
WebServer server(80);

static void webState() {
  static char buf[4096];
  int n = snprintf(buf, sizeof buf,
    "{\"uptime\":%lu,\"app\":{\"name\":\"%s\",\"msg\":\"%s\",\"blink\":%d},"
    "\"boot\":{\"slot\":\"%c\",\"trial\":%d,\"tries\":%d,\"max\":%d,\"rolledBack\":%d,\"verifyMs\":%lu},"
    "\"minVersion\":\"%s\",\"busy\":%d,\"progress\":%d,\"status\":\"%s\",\"slots\":[",
    (unsigned long)millis(), app.name, app.msg, app.blink, 'A' + boot.slot, boot.trial, bl.st.tries, BL_MAX_TRIES,
    boot.rolled_back, (unsigned long)g_verifyMs, ver(bl.st.min_version).c_str(), (int)g_busy, (int)g_progress, (const char *)g_status);
  for (int i = 0; i < 2; i++) {
    const SlotInfo &si = slotInfo[i];
    n += snprintf(buf + n, sizeof buf - n, "%s{\"id\":\"%c\",\"ok\":%d,\"name\":\"%s\",\"ver\":\"%s\",\"status\":\"%s\",\"active\":%d,\"pending\":%d}",
                  i ? "," : "", 'A' + i, si.status == IMG_OK, si.name, si.status == IMG_OK ? ver(si.ver).c_str() : "",
                  img_status_str((img_status_t)si.status), si.active, si.pending);
  }
  n += snprintf(buf + n, sizeof buf - n, "],\"log\":[");
  portENTER_CRITICAL(&logMux);
  uint32_t cnt = logCount, first = cnt > LOG_LINES ? cnt - LOG_LINES : 0;
  LogLine copy[LOG_LINES]; int k = 0;
  for (uint32_t q = first; q < cnt; q++) copy[k++] = logBuf[q % LOG_LINES];
  portEXIT_CRITICAL(&logMux);
  for (int i = k - 1; i >= 0; i--)                                    // newest first
    n += snprintf(buf + n, sizeof buf - n, "%s{\"t\":%lu,\"m\":\"%s\"}", i == k - 1 ? "" : ",", (unsigned long)copy[i].t, copy[i].m);
  snprintf(buf + n, sizeof buf - n, "]}");
  server.send(200, "application/json", buf);
}

static void webCmd() {
  String c = server.arg("c");
  if (c.length() == 1 && strchr("123456re", c.c_str()[0]) && !g_busy) {
    char ch = c.c_str()[0];
    xQueueSend(webCmdQ, &ch, 0);
    server.send(200, "text/plain", "ok");
  } else server.send(409, "text/plain", "busy");
}

void setup() {
  Serial.begin(115200);
  pinMode(PIN_LED_APP, OUTPUT); pinMode(PIN_LED_SEC, OUTPUT);
  Wire.begin(21, 22);
  oled.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  delay(200);
  LOGLN("\n=========== SECURE BOOTLOADER ===========");

  part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, nullptr);
  if (!part || part->size < BL_FLASH_SIZE) { LOGLN("ERROR: data partition not found"); for (;;) delay(1000); }
  bl.flash = &flashDev; bl.verify = verifyMbedtls; bl.pubkey = FW_PUBLIC_KEY;

  int r = bl_boot(&bl, &boot);
  if (r < 0) {
    LOGLN("Blank board: installing factory firmware v1.0 (verified as well)");
    if (bl_factory_install(&bl, IMG_FACTORY_V1, sizeof IMG_FACTORY_V1) == 0) r = bl_boot(&bl, &boot);
  }
  if (r != 1) {
    LOGLN("NO VALID IMAGE: the board stays in the bootloader (recovery mode)");
    for (;;) { digitalWrite(PIN_LED_SEC, !digitalRead(PIN_LED_SEC)); delay(200); }
  }
  if (boot.rolled_back)
    LOGLN("!! The update never confirmed itself: AUTOMATIC ROLLBACK to the previous version");

  uint32_t t0 = micros();
  bl_verify_slot(&bl, boot.slot, nullptr);              // to measure the verification time
  g_verifyMs = (micros() - t0) / 1000;
  LOG("Slot %c: %s v%s | SHA-256 + ECDSA P-256 signature verified in %lu ms\n",
                'A' + boot.slot, boot.hdr.name, ver(boot.hdr.fw_version).c_str(), (unsigned long)((micros() - t0) / 1000));
  LOG("%s -> starting the application\n", boot.trial ? "TRIAL BOOT" : "Confirmed version");
  printSlots();
  LOGLN("=========================================\n");

  parseDescriptor(boot.slot);
  refreshSlots();
  LOG("[APP] %s: \"%s\" (LED every %d ms)\n", app.name, app.msg, app.blink);

  xTaskCreatePinnedToCore(taskDisplay, "display", 4096, nullptr, 1, nullptr, 0);
  xTaskCreatePinnedToCore(taskBlink, "blink", 2048, nullptr, 1, nullptr, 1);
  webCmdQ = xQueueCreate(4, sizeof(char));
  xTaskCreatePinnedToCore(taskApp, "app", 8192, nullptr, 2, nullptr, 1);

  WiFi.begin("Wokwi-GUEST", "", 6);
  for (int k = 0; k < 40 && WiFi.status() != WL_CONNECTED; k++) delay(250);
  server.on("/", []() { server.send(200, "text/html; charset=utf-8", WEB_PAGE); });
  server.on("/api/state", webState);
  server.on("/api/cmd", webCmd);
  server.begin();
  Serial.printf("# Web dashboard: http://localhost:8183 (Wi-Fi %s)\n", WiFi.status() == WL_CONNECTED ? "OK" : "not connected");
}

void loop() {
  server.handleClient();
  delay(2);
}

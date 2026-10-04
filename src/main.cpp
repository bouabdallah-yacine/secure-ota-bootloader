/*
 * ============================================================================
 *  Bootloader sécurisé avec mise à jour signée (ESP32, simulé sur Wokwi)
 * ============================================================================
 *  Au démarrage, le BOOTLOADER choisit le slot à lancer et vérifie sa signature
 *  ECDSA P-256 (mbedTLS). Puis l'APPLICATION démarre : elle fait clignoter la
 *  LED à la vitesse inscrite dans son image et propose des mises à jour.
 *
 *  Menu (moniteur série) :
 *    1  installer v2.0                     (signée, valide)
 *    2  installer v3.0                     (signée mais boguée → retour arrière auto)
 *    3  installer une image piratée        (contenu modifié)
 *    4  installer une image d'une autre clé
 *    5  revenir à v1.0                     (ancienne version → refusée)
 *    6  coupure de courant pendant l'installation de v2.0
 *    s  état des slots    r  redémarrer    e  retour usine
 *
 *  Le cœur (bootloader.c, sha256.c) est du C portable testé sur PC avec des
 *  coupures de courant simulées à chaque écriture flash (test/).
 *
 *  Note : dans le simulateur, l'ESP32 ne peut pas exécuter du code téléchargé.
 *  L'image contient donc la configuration de l'application (clignotement,
 *  message, autotest). Sur une vraie carte, le bootloader sauterait à l'adresse
 *  du slot, comme MCUboot. Toute la logique de sécurité est identique.
 * ============================================================================
 */
#include <Arduino.h>
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

#define PIN_LED_APP  2     // LED verte : clignotement de l'application
#define PIN_LED_SEC  4     // LED rouge : image refusée

Adafruit_SSD1306 oled(128, 64, &Wire, -1);
const esp_partition_t *part = nullptr;

// ---------------------------------------------------------------------------
//  Plateforme : flash réelle de l'ESP32 (partition de données) + mbedTLS
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

// Configuration de l'application lue dans l'image démarrée
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
//  Affichage
// ---------------------------------------------------------------------------
volatile const char *g_status = "";
volatile int g_progress = -1;

// Résumé des slots, recalculé seulement quand il change (la vérification coûte du temps CPU)
char slotTxt[2][24];
static void slotLine(int slot, char *out, size_t n) {
  fw_header_t h;
  img_status_t s = bl_verify_slot(&bl, slot, &h);
  if (s == IMG_OK) snprintf(out, n, "%c: %s%s", 'A' + slot, h.name, slot == bl.st.active ? " *" : "");
  else snprintf(out, n, "%c: %s", 'A' + slot, s == IMG_ERR_EMPTY ? "vide" : "INVALIDE");
}

static void refreshSlots() { slotLine(0, slotTxt[0], sizeof slotTxt[0]); slotLine(1, slotTxt[1], sizeof slotTxt[1]); }

void taskDisplay(void *) {
  for (;;) {
    const char *a = slotTxt[0], *b = slotTxt[1];
    oled.clearDisplay(); oled.setTextColor(SSD1306_WHITE); oled.setTextSize(1);
    oled.setCursor(0, 0);  oled.printf("APP %s", app.name);
    oled.setCursor(0, 10); oled.printf("%s", boot.trial ? "DEMARRAGE D'ESSAI" : "version confirmee");
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
                                    s == bl.st.active ? "  <- active" : (s == bl.st.pending ? "  <- en essai" : ""));
    else Serial.printf("%s\n", img_status_str(st));
  }
  Serial.printf("  version minimale autorisee (anti-retour arriere) : v%s\n", ver(bl.st.min_version).c_str());
}

static void rejectFlash() {
  for (int i = 0; i < 6; i++) { digitalWrite(PIN_LED_SEC, i % 2 == 0); delay(150); }
}

static void installImage(const uint8_t *img, uint32_t n, const char *what, bool powerCut) {
  Serial.printf("\n>>> Telechargement : %s (%lu octets) dans le slot %c\n", what, (unsigned long)n, 'A' + bl_inactive_slot(&bl));
  g_status = "telechargement...";
  if (bl_update_begin(&bl, n)) { Serial.println("    ERREUR flash"); return; }
  for (uint32_t off = 0; off < n; off += 256) {
    uint32_t k = n - off < 256 ? n - off : 256;
    bl_update_write(&bl, off, img + off, k);
    g_progress = (int)((off + k) * 100 / n);
    if (powerCut && off > n / 2) {
      Serial.println("    !!! COUPURE DE COURANT a 50 % de l'ecriture !!!");
      Serial.flush();
      delay(300);
      esp_restart();                                   // comme une vraie coupure
    }
    vTaskDelay(pdMS_TO_TICKS(15));
  }
  g_progress = -1;
  Serial.println("    Verification : SHA-256 du contenu, signature ECDSA P-256, version...");
  uint32_t t0 = micros();
  fw_header_t h;
  img_status_t s = bl_update_finish(&bl, &h);
  uint32_t us = micros() - t0;
  if (s == IMG_OK) {
    Serial.printf("    ACCEPTEE (%lu ms) : %s v%s. Redemarrage pour l'installer...\n", (unsigned long)(us / 1000), h.name, ver(h.fw_version).c_str());
    g_status = "OK -> redemarrage";
    delay(1500);
    esp_restart();
  } else {
    refreshSlots();
    Serial.printf("    REFUSEE : %s\n", img_status_str(s));
    Serial.println("    Le firmware actuel continue de tourner, rien n'a ete installe.");
    g_status = "IMAGE REFUSEE";
    rejectFlash();
  }
}

static void menu() {
  Serial.println("\nMenu : 1 v2.0 valide | 2 v3.0 boguee | 3 image piratee | 4 autre cle | 5 retour v1.0");
  Serial.println("       6 coupure de courant | s etat | r redemarrer | e retour usine");
}

void taskApp(void *) {
  // Autotest de la nouvelle version (démarrage d'essai)
  if (boot.trial) {
    Serial.printf("[APP] Demarrage d'essai %d/%d : autotest en cours...\n", bl.st.tries, BL_MAX_TRIES);
    g_status = "autotest...";
    vTaskDelay(pdMS_TO_TICKS(2500));
    if (app.selftestOk) {
      bl_confirm(&bl);
      boot.trial = 0;
      refreshSlots();
      Serial.printf("[APP] Autotest OK : version confirmee. Version minimale = v%s\n", ver(bl.st.min_version).c_str());
      g_status = "autotest OK";
    } else {
      Serial.println("[APP] Autotest ECHOUE : l'application plante -> le chien de garde redemarre la carte");
      g_status = "PLANTAGE !";
      vTaskDelay(pdMS_TO_TICKS(2000));
      esp_restart();
    }
  }
  menu();
  for (;;) {
    if (Serial.available()) {
      char c = Serial.read();
      switch (c) {
        case '1': installImage(IMG_V2, sizeof IMG_V2, "v2.0 (signee)", false); break;
        case '2': installImage(IMG_V3_BUGGY, sizeof IMG_V3_BUGGY, "v3.0 (signee, boguee)", false); break;
        case '3': installImage(IMG_HACKED, sizeof IMG_HACKED, "image piratee (contenu + hash modifies)", false); break;
        case '4': installImage(IMG_WRONG_KEY, sizeof IMG_WRONG_KEY, "image signee par une autre cle", false); break;
        case '5': installImage(IMG_DOWNGRADE, sizeof IMG_DOWNGRADE, "ancienne version v1.0", false); break;
        case '6': installImage(IMG_V2, sizeof IMG_V2, "v2.0 (avec coupure de courant)", true); break;
        case 's': printSlots(); break;
        case 'r': Serial.println("Redemarrage..."); delay(200); esp_restart(); break;
        case 'e':
          Serial.println("Retour usine : effacement complet...");
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
void setup() {
  Serial.begin(115200);
  pinMode(PIN_LED_APP, OUTPUT); pinMode(PIN_LED_SEC, OUTPUT);
  Wire.begin(21, 22);
  oled.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  delay(200);
  Serial.println("\n========== BOOTLOADER SECURISE ==========");

  part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, nullptr);
  if (!part || part->size < BL_FLASH_SIZE) { Serial.println("ERREUR : partition de donnees introuvable"); for (;;) delay(1000); }
  bl.flash = &flashDev; bl.verify = verifyMbedtls; bl.pubkey = FW_PUBLIC_KEY;

  int r = bl_boot(&bl, &boot);
  if (r < 0) {
    Serial.println("Carte vierge : installation du firmware usine v1.0 (verifie lui aussi)");
    if (bl_factory_install(&bl, IMG_FACTORY_V1, sizeof IMG_FACTORY_V1) == 0) r = bl_boot(&bl, &boot);
  }
  if (r != 1) {
    Serial.println("AUCUNE IMAGE VALIDE : la carte reste dans le bootloader (mode secours)");
    for (;;) { digitalWrite(PIN_LED_SEC, !digitalRead(PIN_LED_SEC)); delay(200); }
  }
  if (boot.rolled_back)
    Serial.println("!! La mise a jour ne s'est jamais confirmee : RETOUR AUTOMATIQUE a la version precedente");

  uint32_t t0 = micros();
  bl_verify_slot(&bl, boot.slot, nullptr);              // pour mesurer le temps de vérification
  Serial.printf("Slot %c : %s v%s | SHA-256 + signature ECDSA P-256 verifiees en %lu ms\n",
                'A' + boot.slot, boot.hdr.name, ver(boot.hdr.fw_version).c_str(), (unsigned long)((micros() - t0) / 1000));
  Serial.printf("%s -> lancement de l'application\n", boot.trial ? "DEMARRAGE D'ESSAI" : "Version confirmee");
  printSlots();
  Serial.println("=========================================\n");

  parseDescriptor(boot.slot);
  refreshSlots();
  Serial.printf("[APP] %s : \"%s\" (LED toutes les %d ms)\n", app.name, app.msg, app.blink);

  xTaskCreatePinnedToCore(taskDisplay, "display", 4096, nullptr, 1, nullptr, 0);
  xTaskCreatePinnedToCore(taskBlink, "blink", 2048, nullptr, 1, nullptr, 1);
  xTaskCreatePinnedToCore(taskApp, "app", 8192, nullptr, 2, nullptr, 1);
}

void loop() { vTaskDelay(portMAX_DELAY); }

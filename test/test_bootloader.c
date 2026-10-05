/*
 * Bootloader tests on a PC: simulated flash (with power cuts) + OpenSSL.
 *   gcc -O2 -Wall -Wextra -Isrc -o t test/test_bootloader.c src/bootloader.c src/sha256.c -lcrypto && ./t
 */
#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include "bootloader.h"
#include "sha256.h"
#include "public_key.h"
#include "demo_images.h"

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static int fails = 0;
#define CHECK(c, ...) do { int ok_ = (c); printf("%s ", ok_ ? "[OK]   " : "[FAIL] "); printf(__VA_ARGS__); \
  printf("\n"); if (!ok_) fails++; } while (0)

/* ---------- Simulated NOR flash: erase = 0xFF, write = logical AND ---------- */
static uint8_t mem[BL_FLASH_SIZE];
static long ops = 0, cut_at = -1;      /* power cut at the n-th operation */
static int dead = 0;

static int f_read(void *c, uint32_t off, void *buf, uint32_t n) { (void)c; memcpy(buf, mem + off, n); return 0; }
static int f_erase(void *c, uint32_t off, uint32_t n) {
  (void)c; if (dead) return -1;
  if (++ops == cut_at) { memset(mem + off, 0xFF, n / 2); dead = 1; return -1; }   /* half-erased */
  memset(mem + off, 0xFF, n); return 0;
}
static int f_write(void *c, uint32_t off, const void *buf, uint32_t n) {
  (void)c; if (dead) return -1;
  const uint8_t *p = buf;
  uint32_t m = n;
  if (++ops == cut_at) { m = n / 2; dead = 1; }                                       /* half-written */
  for (uint32_t i = 0; i < m; i++) mem[off + i] &= p[i];
  return dead ? -1 : 0;
}
static bl_flash_t flash = { f_read, f_write, f_erase, NULL };

/* ---------- ECDSA P-256 via OpenSSL (on the ESP32: mbedTLS) ---------- */
static int verify_openssl(const uint8_t pub[65], const uint8_t hash[32], const uint8_t sig[64]) {
  EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_POINT *q = EC_POINT_new(EC_KEY_get0_group(k));
  EC_POINT_oct2point(EC_KEY_get0_group(k), q, pub, 65, NULL);
  EC_KEY_set_public_key(k, q);
  ECDSA_SIG *s = ECDSA_SIG_new();
  ECDSA_SIG_set0(s, BN_bin2bn(sig, 32, NULL), BN_bin2bn(sig + 32, 32, NULL));
  int ok = ECDSA_do_verify(hash, 32, s, k) == 1;
  ECDSA_SIG_free(s); EC_POINT_free(q); EC_KEY_free(k);
  return ok;
}

static bl_t mk(void) { bl_t b; memset(&b, 0, sizeof b); b.flash = &flash; b.verify = verify_openssl; b.pubkey = FW_PUBLIC_KEY; return b; }

static void power_on(void) { ops = 0; cut_at = -1; dead = 0; }

static img_status_t install(bl_t *b, const uint8_t *img, uint32_t n) {
  if (bl_update_begin(b, n)) return IMG_ERR_FLASH;
  for (uint32_t off = 0; off < n; off += 64) {
    uint32_t k = n - off < 64 ? n - off : 64;
    if (bl_update_write(b, off, img + off, k)) return IMG_ERR_FLASH;
  }
  return bl_update_finish(b, NULL);
}

static uint32_t boot_version(int *trial, int *rolled) {
  bl_t b = mk(); bl_decision_t d;
  if (bl_boot(&b, &d) != 1) return 0;
  if (trial) *trial = d.trial;
  if (rolled) *rolled = d.rolled_back;
  return d.hdr.fw_version;
}

static void factory(void) {
  power_on(); memset(mem, 0xFF, sizeof mem);
  bl_t b = mk(); bl_factory_install(&b, IMG_FACTORY_V1, sizeof IMG_FACTORY_V1);
}

int main(void) {
  /* SHA-256: official NIST test vectors */
  uint8_t h[32]; char hex[65];
  sha256("abc", 3, h);
  for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", h[i]);
  CHECK(!strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "SHA-256(\"abc\") matches NIST");

  /* 1. Factory install + boot */
  factory();
  int trial = -1, rolled = -1;
  CHECK(boot_version(&trial, &rolled) == 0x010000 && trial == 0, "factory: boots v1.0 (slot A)");

  /* 2. Valid v2 update → trial boot → confirmation */
  power_on(); bl_t b = mk(); bl_decision_t d; bl_boot(&b, &d);
  CHECK(install(&b, IMG_V2, sizeof IMG_V2) == IMG_OK, "signed v2.0: accepted and written to slot B");
  power_on(); b = mk(); bl_boot(&b, &d);
  CHECK(d.hdr.fw_version == 0x020000 && d.trial == 1 && d.slot == 1, "reboot: v2.0 in trial boot (slot B)");
  bl_confirm(&b);
  CHECK(boot_version(&trial, NULL) == 0x020000 && trial == 0, "after confirmation: v2.0 is permanent");

  /* 3. Attacks */
  power_on(); b = mk(); bl_boot(&b, &d);
  img_status_t s = install(&b, IMG_HACKED, sizeof IMG_HACKED);
  CHECK(s == IMG_ERR_SIGNATURE, "tampered image (content + hash modified): rejected → %s", img_status_str(s));
  s = install(&b, IMG_WRONG_KEY, sizeof IMG_WRONG_KEY);
  CHECK(s == IMG_ERR_SIGNATURE, "image signed with another key: rejected → %s", img_status_str(s));
  s = install(&b, IMG_DOWNGRADE, sizeof IMG_DOWNGRADE);
  CHECK(s == IMG_ERR_DOWNGRADE, "downgrade to v1.0 (authentic but old): rejected → %s", img_status_str(s));
  uint8_t corrupt[sizeof IMG_V2]; memcpy(corrupt, IMG_V2, sizeof corrupt); corrupt[3000] ^= 1;
  s = install(&b, corrupt, sizeof corrupt);
  CHECK(s == IMG_ERR_HASH, "single bit flipped in the payload: rejected → %s", img_status_str(s));
  CHECK(boot_version(NULL, NULL) == 0x020000, "after the attacks: v2.0 still running");

  /* 4. Buggy version: never confirmed → automatic rollback after 3 attempts */
  power_on(); b = mk(); bl_boot(&b, &d);
  CHECK(install(&b, IMG_V3_BUGGY, sizeof IMG_V3_BUGGY) == IMG_OK, "v3.0 (signed but buggy): accepted");
  int boots_v3 = 0;
  for (int i = 0; i < 5; i++) { power_on(); if (boot_version(&trial, &rolled) == 0x030000) boots_v3++; else break; }
  CHECK(boots_v3 == BL_MAX_TRIES && rolled == 1, "v3.0 boots %d times without confirming → automatic rollback to v2.0", boots_v3);
  CHECK(boot_version(&trial, NULL) == 0x020000 && trial == 0, "v2.0 active again");

  /* 5. Power cut at EVERY flash operation: while writing the update,
        then during the trial boot and the confirmation */
  int all_safe = 1, n_install, n_confirm;
  factory(); power_on(); { bl_t t = mk(); bl_boot(&t, &d); ops = 0; install(&t, IMG_V2, sizeof IMG_V2); n_install = (int)ops;
    power_on(); t = mk(); bl_boot(&t, &d); bl_confirm(&t); n_confirm = (int)ops; }
  for (int phase = 0; phase < 2; phase++) {
    int n = phase ? n_confirm : n_install;
    for (int cut = 1; cut <= n; cut++) {
      factory(); power_on();
      bl_t t = mk(); bl_boot(&t, &d);
      if (phase == 0) { ops = 0; cut_at = cut; install(&t, IMG_V2, sizeof IMG_V2); }
      else { install(&t, IMG_V2, sizeof IMG_V2); power_on(); cut_at = cut; t = mk(); bl_boot(&t, &d); bl_confirm(&t); }
      power_on();
      uint32_t v = boot_version(NULL, NULL);
      if (v != 0x010000 && v != 0x020000) all_safe = 0;
    }
  }
  CHECK(all_safe, "power cut tested at each of the %d flash operations (write: %d, trial + confirmation: %d): "
        "the board always reboots on a valid signed image", n_install + n_confirm, n_install, n_confirm);

  /* 6. Active slot destroyed: fall back to the other slot */
  factory(); power_on(); b = mk(); bl_boot(&b, &d); install(&b, IMG_V2, sizeof IMG_V2);
  power_on(); b = mk(); bl_boot(&b, &d); bl_confirm(&b);           /* v2 active in B, v1 in A */
  mem[BL_SLOT_B + 500] ^= 0xFF;                                    /* B damaged (flash wear) */
  power_on();
  CHECK(boot_version(NULL, NULL) == 0, "active slot damaged and other slot older: refuses to boot an outdated version");

  printf("\n%s: %d failure(s)\n", fails ? "FAILED" : "ALL TESTS PASSED", fails);
  return fails != 0;
}

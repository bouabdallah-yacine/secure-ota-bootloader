/*
 * ============================================================================
 *  Secure bootloader: signature verification, A/B slots, rollback
 * ============================================================================
 *  Flash memory:  [ slot A ][ slot B ][ state 0 ][ state 1 ]
 *
 *  - An update is ALWAYS written to the inactive slot: the running firmware
 *    is never overwritten, so a power cut cannot break anything.
 *  - Before it is booted, an image is verified: SHA-256 of the payload +
 *    ECDSA P-256 signature with the manufacturer's public key.
 *  - Anti-rollback: a version older than the last confirmed version is
 *    rejected (it may contain known vulnerabilities).
 *  - Trial boot: the new version must confirm itself after its self-test.
 *    Otherwise, after 3 failed boots, it automatically falls back to the old one.
 *  - The state is written twice (2 sectors, sequence number + CRC32):
 *    a power cut while it is being written always leaves one valid copy.
 * ============================================================================
 */
#pragma once
#include <stdint.h>
#include "fw_image.h"
#ifdef __cplusplus
extern "C" {
#endif

#define BL_SECTOR      4096u
#define BL_SLOT_SIZE   (8u * BL_SECTOR)          /* 32 KB per slot */
#define BL_SLOT_A      0u
#define BL_SLOT_B      BL_SLOT_SIZE
#define BL_STATE0      (2u * BL_SLOT_SIZE)
#define BL_STATE1      (BL_STATE0 + BL_SECTOR)
#define BL_FLASH_SIZE  (BL_STATE1 + BL_SECTOR)
#define BL_MAX_TRIES   3
#define BL_NONE        0xFF

/* Flash memory access (provided by the platform: ESP32 or PC simulation) */
typedef struct {
  int (*read)(void *ctx, uint32_t off, void *buf, uint32_t n);
  int (*write)(void *ctx, uint32_t off, const void *buf, uint32_t n);
  int (*erase)(void *ctx, uint32_t off, uint32_t n);       /* in 4 KB sectors */
  void *ctx;
} bl_flash_t;

/* ECDSA P-256 verification (provided by the platform: mbedTLS / OpenSSL) */
typedef int (*bl_verify_fn)(const uint8_t pub[65], const uint8_t hash[32], const uint8_t sig[64]);

typedef struct {
  uint32_t magic, seq;
  uint8_t  active;        /* 0 = A, 1 = B */
  uint8_t  pending;       /* slot on trial, or BL_NONE */
  uint8_t  tries;         /* trial boots already attempted */
  uint8_t  rolled_back;   /* 1 if the last boot cancelled an update */
  uint32_t min_version;   /* anti-rollback counter */
  uint32_t crc;
} bl_state_t;

typedef enum {
  IMG_OK = 0, IMG_ERR_EMPTY, IMG_ERR_FORMAT, IMG_ERR_HASH, IMG_ERR_SIGNATURE, IMG_ERR_DOWNGRADE, IMG_ERR_FLASH
} img_status_t;

typedef struct {
  bl_flash_t   *flash;
  bl_verify_fn  verify;
  const uint8_t *pubkey;
  bl_state_t    st;
  uint32_t      upd_size;
} bl_t;

typedef struct { int slot; int trial; int rolled_back; fw_header_t hdr; } bl_decision_t;

const char  *img_status_str(img_status_t s);
img_status_t bl_verify_slot(bl_t *b, int slot, fw_header_t *hdr);

/* At boot: 1 = image selected (in d), 0 = no valid image, -1 = blank board */
int  bl_boot(bl_t *b, bl_decision_t *d);
int  bl_factory_install(bl_t *b, const uint8_t *img, uint32_t n);

/* Update (called by the application) */
int          bl_update_begin(bl_t *b, uint32_t size);
int          bl_update_write(bl_t *b, uint32_t off, const void *data, uint32_t n);
img_status_t bl_update_finish(bl_t *b, fw_header_t *hdr);
int          bl_confirm(bl_t *b);        /* the application confirms the trial version */
int          bl_inactive_slot(const bl_t *b);

static inline uint32_t bl_slot_addr(int slot) { return slot ? BL_SLOT_B : BL_SLOT_A; }

#ifdef __cplusplus
}
#endif

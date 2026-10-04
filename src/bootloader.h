/*
 * ============================================================================
 *  Bootloader sécurisé : vérification de signature, slots A/B, retour arrière
 * ============================================================================
 *  Mémoire flash :  [ slot A ][ slot B ][ état 0 ][ état 1 ]
 *
 *  - Une mise à jour s'écrit TOUJOURS dans le slot inactif : le firmware qui
 *    tourne n'est jamais écrasé, une coupure de courant ne peut rien casser.
 *  - Avant d'être démarrée, une image est vérifiée : SHA-256 du contenu +
 *    signature ECDSA P-256 avec la clé publique du fabricant.
 *  - Anti-retour arrière : une version plus ancienne que la dernière version
 *    confirmée est refusée (elle peut contenir des failles connues).
 *  - Démarrage d'essai : la nouvelle version doit se confirmer après son
 *    autotest. Sinon, après 3 démarrages ratés, retour automatique à l'ancienne.
 *  - L'état est écrit en double (2 secteurs, numéro de séquence + CRC32) :
 *    une coupure pendant son écriture laisse toujours une copie valide.
 * ============================================================================
 */
#pragma once
#include <stdint.h>
#include "fw_image.h"
#ifdef __cplusplus
extern "C" {
#endif

#define BL_SECTOR      4096u
#define BL_SLOT_SIZE   (8u * BL_SECTOR)          /* 32 Ko par slot */
#define BL_SLOT_A      0u
#define BL_SLOT_B      BL_SLOT_SIZE
#define BL_STATE0      (2u * BL_SLOT_SIZE)
#define BL_STATE1      (BL_STATE0 + BL_SECTOR)
#define BL_FLASH_SIZE  (BL_STATE1 + BL_SECTOR)
#define BL_MAX_TRIES   3
#define BL_NONE        0xFF

/* Accès à la mémoire flash (fourni par la plateforme : ESP32 ou simulation PC) */
typedef struct {
  int (*read)(void *ctx, uint32_t off, void *buf, uint32_t n);
  int (*write)(void *ctx, uint32_t off, const void *buf, uint32_t n);
  int (*erase)(void *ctx, uint32_t off, uint32_t n);       /* par secteurs de 4 Ko */
  void *ctx;
} bl_flash_t;

/* Vérification ECDSA P-256 (fournie par la plateforme : mbedTLS / OpenSSL) */
typedef int (*bl_verify_fn)(const uint8_t pub[65], const uint8_t hash[32], const uint8_t sig[64]);

typedef struct {
  uint32_t magic, seq;
  uint8_t  active;        /* 0 = A, 1 = B */
  uint8_t  pending;       /* slot en essai, ou BL_NONE */
  uint8_t  tries;         /* démarrages d'essai déjà tentés */
  uint8_t  rolled_back;   /* 1 si le dernier démarrage a annulé une mise à jour */
  uint32_t min_version;   /* compteur anti-retour arrière */
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

/* Au démarrage : 1 = image choisie (dans d), 0 = aucune image valide, -1 = carte vierge */
int  bl_boot(bl_t *b, bl_decision_t *d);
int  bl_factory_install(bl_t *b, const uint8_t *img, uint32_t n);

/* Mise à jour (appelée par l'application) */
int          bl_update_begin(bl_t *b, uint32_t size);
int          bl_update_write(bl_t *b, uint32_t off, const void *data, uint32_t n);
img_status_t bl_update_finish(bl_t *b, fw_header_t *hdr);
int          bl_confirm(bl_t *b);        /* l'application valide la version en essai */
int          bl_inactive_slot(const bl_t *b);

static inline uint32_t bl_slot_addr(int slot) { return slot ? BL_SLOT_B : BL_SLOT_A; }

#ifdef __cplusplus
}
#endif

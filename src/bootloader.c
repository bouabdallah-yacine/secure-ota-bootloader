#include "bootloader.h"
#include "sha256.h"
#include <string.h>
#include <stddef.h>

#define STATE_MAGIC 0x42535441u   /* "ATSB" */

const char *img_status_str(img_status_t s) {
  switch (s) {
    case IMG_OK:            return "image valide";
    case IMG_ERR_EMPTY:     return "slot vide";
    case IMG_ERR_FORMAT:    return "format invalide ou image incomplete";
    case IMG_ERR_HASH:      return "contenu modifie (SHA-256 incorrect)";
    case IMG_ERR_SIGNATURE: return "signature invalide (pas signee par le fabricant)";
    case IMG_ERR_DOWNGRADE: return "version trop ancienne (anti-retour arriere)";
    case IMG_ERR_FLASH:     return "erreur d'ecriture flash";
  }
  return "?";
}

static uint32_t crc32(const void *data, size_t n) {
  const uint8_t *p = (const uint8_t *)data;
  uint32_t c = 0xFFFFFFFFu;
  while (n--) { c ^= *p++; for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1))); }
  return ~c;
}

/* ---------------------------------------------------------------------------
 *  Vérification d'une image : format → hash du contenu → signature
 * ------------------------------------------------------------------------- */
img_status_t bl_verify_slot(bl_t *b, int slot, fw_header_t *hdr) {
  fw_header_t h;
  uint32_t base = bl_slot_addr(slot);
  if (b->flash->read(b->flash->ctx, base, &h, sizeof h)) return IMG_ERR_FLASH;
  if (h.magic == 0xFFFFFFFFu) return IMG_ERR_EMPTY;
  if (h.magic != FW_MAGIC || h.hdr_version != FW_HDR_VERSION ||
      h.payload_size == 0 || h.payload_size > BL_SLOT_SIZE - FW_HDR_SIZE) return IMG_ERR_FORMAT;

  sha256_ctx c; sha256_init(&c);
  uint8_t buf[256];
  for (uint32_t off = 0; off < h.payload_size; off += sizeof buf) {
    uint32_t n = h.payload_size - off < sizeof buf ? h.payload_size - off : (uint32_t)sizeof buf;
    if (b->flash->read(b->flash->ctx, base + FW_HDR_SIZE + off, buf, n)) return IMG_ERR_FLASH;
    sha256_update(&c, buf, n);
  }
  uint8_t digest[32];
  sha256_final(&c, digest);
  if (memcmp(digest, h.sha256, 32) != 0) return IMG_ERR_HASH;

  uint8_t hh[32];
  sha256(&h, FW_SIGNED_SIZE, hh);                      /* l'en-tête contient le hash du contenu */
  if (!b->verify(b->pubkey, hh, h.signature)) return IMG_ERR_SIGNATURE;

  if (hdr) *hdr = h;
  return IMG_OK;
}

/* ---------------------------------------------------------------------------
 *  État persistant en double exemplaire (résiste aux coupures de courant)
 * ------------------------------------------------------------------------- */
static int state_valid(const bl_state_t *s) {
  return s->magic == STATE_MAGIC && s->crc == crc32(s, offsetof(bl_state_t, crc));
}

static int load_state(bl_t *b) {
  bl_state_t s0, s1;
  b->flash->read(b->flash->ctx, BL_STATE0, &s0, sizeof s0);
  b->flash->read(b->flash->ctx, BL_STATE1, &s1, sizeof s1);
  int v0 = state_valid(&s0), v1 = state_valid(&s1);
  if (!v0 && !v1) return 0;
  b->st = (v0 && (!v1 || s0.seq > s1.seq)) ? s0 : s1;
  return 1;
}

static int save_state(bl_t *b) {
  b->st.magic = STATE_MAGIC;
  b->st.seq++;
  b->st.crc = crc32(&b->st, offsetof(bl_state_t, crc));
  uint32_t addr = (b->st.seq & 1) ? BL_STATE1 : BL_STATE0;    /* on alterne les secteurs */
  if (b->flash->erase(b->flash->ctx, addr, BL_SECTOR)) return -1;
  return b->flash->write(b->flash->ctx, addr, &b->st, sizeof b->st);
}

/* ---------------------------------------------------------------------------
 *  Décision de démarrage
 * ------------------------------------------------------------------------- */
int bl_boot(bl_t *b, bl_decision_t *d) {
  memset(d, 0, sizeof *d);
  if (!load_state(b)) return -1;                       /* carte vierge : installation usine */
  int changed = 0;
  b->st.rolled_back = 0;

  if (b->st.pending != BL_NONE) {
    fw_header_t h;
    img_status_t s = bl_verify_slot(b, b->st.pending, &h);
    if (s == IMG_OK && h.fw_version < b->st.min_version) s = IMG_ERR_DOWNGRADE;
    if (s != IMG_OK || b->st.tries >= BL_MAX_TRIES) {
      b->st.pending = BL_NONE;                         /* annulation : retour à l'ancienne version */
      b->st.rolled_back = 1;
      changed = 1;
    } else {
      b->st.tries++;
      if (save_state(b)) return 0;
      d->slot = b->st.pending; d->trial = 1; d->hdr = h;
      return 1;
    }
  }

  fw_header_t h;
  img_status_t s = bl_verify_slot(b, b->st.active, &h);
  if (s == IMG_OK && h.fw_version < b->st.min_version) s = IMG_ERR_DOWNGRADE;
  if (s != IMG_OK) {                                   /* slot actif abîmé : on tente l'autre */
    int other = !b->st.active;
    s = bl_verify_slot(b, other, &h);
    if (s != IMG_OK || h.fw_version < b->st.min_version) return 0;
    b->st.active = (uint8_t)other;
    changed = 1;
  }
  d->rolled_back = b->st.rolled_back;
  if (changed && save_state(b)) return 0;
  d->slot = b->st.active; d->trial = 0; d->hdr = h;
  return 1;
}

int bl_factory_install(bl_t *b, const uint8_t *img, uint32_t n) {
  if (n > BL_SLOT_SIZE) return -1;
  if (b->flash->erase(b->flash->ctx, BL_SLOT_A, BL_SLOT_SIZE)) return -1;
  if (b->flash->write(b->flash->ctx, BL_SLOT_A, img, n)) return -1;
  fw_header_t h;
  if (bl_verify_slot(b, 0, &h) != IMG_OK) return -1;   /* même l'image usine est vérifiée */
  memset(&b->st, 0, sizeof b->st);
  b->st.active = 0; b->st.pending = BL_NONE; b->st.min_version = h.fw_version;
  b->flash->erase(b->flash->ctx, BL_STATE0, 2 * BL_SECTOR);
  return save_state(b);
}

/* ---------------------------------------------------------------------------
 *  Mise à jour : écriture dans le slot inactif, vérification, démarrage d'essai
 * ------------------------------------------------------------------------- */
int bl_inactive_slot(const bl_t *b) { return !b->st.active; }

int bl_update_begin(bl_t *b, uint32_t size) {
  if (size < FW_HDR_SIZE || size > BL_SLOT_SIZE) return -1;
  if (b->st.pending != BL_NONE) {                      /* une mise à jour non confirmée est abandonnée */
    b->st.pending = BL_NONE;
    if (save_state(b)) return -1;
  }
  b->upd_size = size;
  return b->flash->erase(b->flash->ctx, bl_slot_addr(bl_inactive_slot(b)), BL_SLOT_SIZE);
}

int bl_update_write(bl_t *b, uint32_t off, const void *data, uint32_t n) {
  if (off + n > b->upd_size) return -1;
  return b->flash->write(b->flash->ctx, bl_slot_addr(bl_inactive_slot(b)) + off, data, n);
}

img_status_t bl_update_finish(bl_t *b, fw_header_t *hdr) {
  fw_header_t h, cur;
  int slot = bl_inactive_slot(b);
  img_status_t s = bl_verify_slot(b, slot, &h);
  if (s != IMG_OK) return s;
  if (bl_verify_slot(b, b->st.active, &cur) == IMG_OK && h.fw_version <= cur.fw_version) return IMG_ERR_DOWNGRADE;
  if (h.fw_version < b->st.min_version) return IMG_ERR_DOWNGRADE;
  b->st.pending = (uint8_t)slot;
  b->st.tries = 0;
  if (save_state(b)) return IMG_ERR_FLASH;
  if (hdr) *hdr = h;
  return IMG_OK;
}

int bl_confirm(bl_t *b) {
  if (b->st.pending == BL_NONE) return 0;              /* rien à confirmer */
  fw_header_t h;
  if (bl_verify_slot(b, b->st.pending, &h) != IMG_OK) return -1;
  b->st.active = b->st.pending;
  b->st.pending = BL_NONE;
  b->st.tries = 0;
  b->st.min_version = h.fw_version;                    /* le compteur anti-retour arrière avance */
  return save_state(b);
}

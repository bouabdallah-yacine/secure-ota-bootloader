/*
 * Format d'une image firmware signée (128 octets d'en-tête + contenu).
 *
 *   ┌──────────────── en-tête (128 octets, petit-boutiste) ────────────────┐
 *   │ magic "FWIM" │ version en-tête │ drapeaux │ version firmware │ taille │
 *   │ SHA-256 du contenu (32)  │ nom (16)  │ signature ECDSA P-256 (64)    │
 *   └───────────────────────────────────────────────────────────────────────┘
 *   │ contenu du firmware (taille octets)                                   │
 *
 * La signature porte sur les 64 premiers octets de l'en-tête, qui contiennent
 * le hash du contenu : modifier UN SEUL octet, n'importe où, casse la signature.
 */
#pragma once
#include <stdint.h>

#define FW_MAGIC        0x4D495746u   /* "FWIM" */
#define FW_HDR_VERSION  1
#define FW_HDR_SIZE     128
#define FW_SIGNED_SIZE  64            /* octets couverts par la signature */

typedef struct {
  uint32_t magic;
  uint16_t hdr_version;
  uint16_t flags;
  uint32_t fw_version;       /* (majeur << 16) | (mineur << 8) | correctif */
  uint32_t payload_size;
  uint8_t  sha256[32];       /* hash du contenu */
  char     name[16];         /* ex. "v2.0 rapide" */
  uint8_t  signature[64];    /* r || s, ECDSA P-256 sur SHA-256(en-tête[0..63]) */
} fw_header_t;

#ifdef __cplusplus
static_assert(sizeof(fw_header_t) == FW_HDR_SIZE, "en-tete : 128 octets");
#else
_Static_assert(sizeof(fw_header_t) == FW_HDR_SIZE, "en-tete : 128 octets");
#endif

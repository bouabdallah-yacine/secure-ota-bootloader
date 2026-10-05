/*
 * Signed firmware image format (128-byte header + payload).
 *
 *   ┌─────────────────── header (128 bytes, little-endian) ─────────────────┐
 *   │ magic "FWIM" │ header version │ flags │ firmware version │ size       │
 *   │ SHA-256 of payload (32)  │ name (16) │ ECDSA P-256 signature (64)     │
 *   └───────────────────────────────────────────────────────────────────────┘
 *   │ firmware payload (size bytes)                                         │
 *
 * The signature covers the first 64 bytes of the header, which contain the
 * payload hash: changing a SINGLE byte, anywhere, breaks the signature.
 */
#pragma once
#include <stdint.h>

#define FW_MAGIC        0x4D495746u   /* "FWIM" */
#define FW_HDR_VERSION  1
#define FW_HDR_SIZE     128
#define FW_SIGNED_SIZE  64            /* bytes covered by the signature */

typedef struct {
  uint32_t magic;
  uint16_t hdr_version;
  uint16_t flags;
  uint32_t fw_version;       /* (major << 16) | (minor << 8) | patch */
  uint32_t payload_size;
  uint8_t  sha256[32];       /* payload hash */
  char     name[16];         /* e.g. "v2.0 fast" */
  uint8_t  signature[64];    /* r || s, ECDSA P-256 over SHA-256(header[0..63]) */
} fw_header_t;

#ifdef __cplusplus
static_assert(sizeof(fw_header_t) == FW_HDR_SIZE, "header: 128 bytes");
#else
_Static_assert(sizeof(fw_header_t) == FW_HDR_SIZE, "header: 128 bytes");
#endif

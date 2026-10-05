/*
 * tinyimg - a deliberately small binary "image" parser used as a
 * KavachForge demonstration target.
 *
 * Wire format (little-endian):
 *   offset 0 : 4 bytes  magic  = "TIMG"
 *   offset 4 : 1 byte   version
 *   offset 5 : 1 byte   n_channels   (number of channel records that follow)
 *   offset 6 : n_channels * 2 bytes  (each: 1 byte id, 1 byte depth)
 *
 * The parser decodes the channel table into a fixed on-stack array.
 *
 * SEEDED VULNERABILITY (CWE-787: Out-of-bounds Write):
 *   `n_channels` is attacker-controlled (0-255) but the destination
 *   array `channels` only has room for TINYIMG_MAX_CHANNELS (16) entries.
 *   The decode loop trusts n_channels and writes past the array when
 *   n_channels > 16. AddressSanitizer reports a stack-buffer-overflow.
 *
 * The bug is gated behind the 4-byte "TIMG" magic, so blind mutation
 * must first discover the magic; a structure-aware seed reaches it fast.
 */
#include "tinyimg.h"
#include <string.h>
#include <stdlib.h>

#define TINYIMG_MAX_CHANNELS 16

int tinyimg_parse(const uint8_t *data, size_t size, tinyimg_info *out) {
    if (data == NULL || out == NULL) return TINYIMG_ERR_ARG;
    if (size < 6) return TINYIMG_ERR_SHORT;

    /* magic gate */
    if (memcmp(data, "TIMG", 4) != 0) return TINYIMG_ERR_MAGIC;

    uint8_t version    = data[4];
    uint8_t n_channels = data[5];
    if (version != 1) return TINYIMG_ERR_VERSION;

    struct { uint8_t id; uint8_t depth; } channels[TINYIMG_MAX_CHANNELS];

    /* Need enough bytes for the declared channel table. */
    if (size < (size_t)6 + (size_t)n_channels * 2) return TINYIMG_ERR_SHORT;

    /* VULN: n_channels is not clamped to TINYIMG_MAX_CHANNELS. */
    for (uint8_t i = 0; i < n_channels; i++) {
        channels[i].id    = data[6 + i * 2];
        channels[i].depth = data[6 + i * 2 + 1];
    }

    out->version    = version;
    out->n_channels = n_channels;
    out->first_id    = (n_channels > 0) ? channels[0].id : 0;
    return TINYIMG_OK;
}

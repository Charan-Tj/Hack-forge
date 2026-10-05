/*
 * sigpkt - a digest-gated packet parser used as a KavachForge target.
 *
 * Wire format (little-endian):
 *   offset 0 : 4 bytes  magic   = "SPK1"
 *   offset 4 : 1 byte   n_fields
 *   offset 5 : 4 bytes  digest  = FNV1a(body) XOR SIGPKT_DIGEST_KEY
 *   offset 9 : body     = n_fields * 2 bytes (uint16 values)
 *
 * The body is only decoded when the digest matches. That gate is the point:
 * a coverage-guided fuzzer cannot solve a 32-bit keyed digest by mutation,
 * while a generator that understands the format computes it directly. This
 * makes the seed-generator feature's contribution measurable and honest.
 *
 * SEEDED VULNERABILITY (CWE-787): n_fields (0-255) is used as the loop bound
 * when decoding into a fixed 32-entry table.
 */
#include "sigpkt.h"
#include <string.h>

#define SIGPKT_MAX_FIELDS 32

uint32_t sigpkt_fnv1a(const uint8_t *p, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

int sigpkt_parse(const uint8_t *data, size_t size, sigpkt_info *out) {
    if (data == NULL || out == NULL) return SIGPKT_ERR_ARG;
    if (size < 9) return SIGPKT_ERR_SHORT;
    if (memcmp(data, "SPK1", 4) != 0) return SIGPKT_ERR_MAGIC;

    uint8_t n_fields = data[4];
    uint32_t digest = (uint32_t)data[5] | ((uint32_t)data[6] << 8) |
                      ((uint32_t)data[7] << 16) | ((uint32_t)data[8] << 24);
    size_t body_len = (size_t)n_fields * 2;
    if (size < 9 + body_len) return SIGPKT_ERR_SHORT;

    uint32_t want = sigpkt_fnv1a(data + 9, body_len) ^ SIGPKT_DIGEST_KEY;
    if (digest != want) return SIGPKT_ERR_DIGEST;

    uint16_t values[SIGPKT_MAX_FIELDS];
    /* VULN: n_fields is not checked against SIGPKT_MAX_FIELDS. */
    for (uint8_t i = 0; i < n_fields; i++) {
        values[i] = (uint16_t)(data[9 + i * 2] | (data[10 + i * 2] << 8));
    }

    out->n_fields    = n_fields;
    out->digest      = digest;
    out->first_value = n_fields ? values[0] : 0;
    return SIGPKT_OK;
}

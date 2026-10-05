/*
 * urlparse - a tiny "scheme://host/path" parser used as the KavachForge
 * UNFUZZED target: it ships with NO harness and NO task. KavachForge's
 * `kavach harness` command discovers the fuzzable entry point, synthesizes a
 * libFuzzer harness, validates it, and only then runs the normal loop.
 *
 * SEEDED VULNERABILITY (CWE-787): the host component is copied into a fixed
 * 32-byte field with no bound check, so a long host overflows it.
 */
#include "urlparse.h"
#include <string.h>

int urlparse(const uint8_t *data, size_t size, urlinfo *out) {
    if (data == NULL || out == NULL) return URLPARSE_ERR_ARG;
    if (size < 4) return URLPARSE_ERR_SHORT;

    /* scheme: up to the "://" separator, capped at 7 chars */
    size_t i = 0;
    while (i < size && i < 7 && data[i] != ':') {
        out->scheme[i] = (char)data[i];
        i++;
    }
    out->scheme[i] = '\0';
    if (i + 3 > size || data[i] != ':' || data[i + 1] != '/' || data[i + 2] != '/')
        return URLPARSE_ERR_SCHEME;
    size_t h = i + 3;

    /* host: up to '/' or end of input */
    size_t start = h;
    while (h < size && data[h] != '/') h++;
    size_t host_len = h - start;

    /* VULN: host_len is not checked against sizeof(out->host). */
    memcpy(out->host, data + start, host_len);
    out->host[host_len] = '\0';
    out->host_len = (uint16_t)host_len;
    return URLPARSE_OK;
}

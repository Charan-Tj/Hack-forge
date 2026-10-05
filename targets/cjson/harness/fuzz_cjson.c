/*
 * libFuzzer harness for cJSON (vendored upstream, MIT - see ../LICENSE).
 * Parses the fuzz input as JSON and, on success, round-trips it through the
 * printer, then frees. This exercises the real parser + printer paths of a
 * widely-used open-source C library. KavachForge treats cJSON as a normal
 * target: discover, reproduce, (attempt to) repair, and prove.
 *
 * Do not edit as part of patching.
 */
#include "cJSON.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (json) {
        char *out = cJSON_Print(json);
        if (out) free(out);
        cJSON_Delete(json);
    }
    free(buf);
    return 0;
}

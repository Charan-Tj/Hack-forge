/*
 * cleanjson - a tiny, intentionally SAFE bounded integer-list parser used
 * as the KavachForge control target. There is no seeded vulnerability; a
 * bounded fuzzing run should report no verified crash, demonstrating that
 * the system does not invent findings.
 *
 * Wire format:
 *   offset 0 : 4 bytes magic = "CJSN"
 *   offset 4 : 1 byte  count
 *   then `count` bytes, each a value 0-255; parser sums them with every
 *   access bounds-checked.
 */
#include "cleanjson.h"
#include <string.h>

int cleanjson_parse(const uint8_t *data, size_t size, cleanjson_result *out) {
    if (data == NULL || out == NULL) return CLEANJSON_ERR_ARG;
    if (size < 5) return CLEANJSON_ERR_SHORT;
    if (memcmp(data, "CJSN", 4) != 0) return CLEANJSON_ERR_MAGIC;

    uint8_t count = data[4];
    uint32_t sum = 0;
    uint32_t seen = 0;

    for (uint8_t i = 0; i < count; i++) {
        size_t idx = (size_t)5 + i;
        if (idx >= size) break;          /* bounds-checked: no overflow */
        sum += data[idx];
        seen++;
    }

    out->count = seen;
    out->sum   = sum;
    return CLEANJSON_OK;
}

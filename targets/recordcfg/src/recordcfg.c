/*
 * recordcfg - a tiny TLV ("type-length-value") config record parser used
 * as a second KavachForge demonstration target (distinct bug class).
 *
 * Wire format (little-endian):
 *   offset 0 : 4 bytes  magic = "RCF1"
 *   offset 4 : 1 byte   n_records
 *   then n_records records, each:
 *       1 byte  type
 *       1 byte  length
 *       length bytes value
 *
 * Each record's value is copied into a fixed 32-byte scratch field on the
 * heap-allocated record struct.
 *
 * SEEDED VULNERABILITY (CWE-787 / CWE-120: unchecked copy length):
 *   `length` (0-255) is used directly as the memcpy size into a 32-byte
 *   buffer with no bound check, so a record with length > 32 overflows the
 *   heap allocation. AddressSanitizer reports a heap-buffer-overflow.
 */
#include "recordcfg.h"
#include <string.h>
#include <stdlib.h>

#define RECORDCFG_VALUE_CAP 32

typedef struct {
    uint8_t type;
    uint8_t length;
    uint8_t value[RECORDCFG_VALUE_CAP];
} rcf_record;

int recordcfg_parse(const uint8_t *data, size_t size, recordcfg_summary *out) {
    if (data == NULL || out == NULL) return RECORDCFG_ERR_ARG;
    if (size < 5) return RECORDCFG_ERR_SHORT;
    if (memcmp(data, "RCF1", 4) != 0) return RECORDCFG_ERR_MAGIC;

    uint8_t n_records = data[4];
    size_t off = 5;
    uint32_t total_value_bytes = 0;

    rcf_record *rec = (rcf_record *)malloc(sizeof(rcf_record));
    if (rec == NULL) return RECORDCFG_ERR_ARG;

    for (uint8_t i = 0; i < n_records; i++) {
        if (off + 2 > size) { free(rec); return RECORDCFG_ERR_SHORT; }
        rec->type   = data[off];
        rec->length = data[off + 1];
        off += 2;

        if (off + rec->length > size) { free(rec); return RECORDCFG_ERR_SHORT; }

        /* VULN: rec->length is not checked against RECORDCFG_VALUE_CAP. */
        memcpy(rec->value, data + off, rec->length);
        off += rec->length;
        total_value_bytes += rec->length;
    }

    out->n_records         = n_records;
    out->total_value_bytes = total_value_bytes;
    free(rec);
    return RECORDCFG_OK;
}

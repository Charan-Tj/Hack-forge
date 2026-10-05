#ifndef RECORDCFG_H
#define RECORDCFG_H

#include <stddef.h>
#include <stdint.h>

enum {
    RECORDCFG_OK        =  0,
    RECORDCFG_ERR_ARG   = -1,
    RECORDCFG_ERR_SHORT = -2,
    RECORDCFG_ERR_MAGIC = -3
};

typedef struct {
    uint8_t  n_records;
    uint32_t total_value_bytes;
} recordcfg_summary;

int recordcfg_parse(const uint8_t *data, size_t size, recordcfg_summary *out);

#endif /* RECORDCFG_H */

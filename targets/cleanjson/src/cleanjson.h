#ifndef CLEANJSON_H
#define CLEANJSON_H

#include <stddef.h>
#include <stdint.h>

enum {
    CLEANJSON_OK        =  0,
    CLEANJSON_ERR_ARG   = -1,
    CLEANJSON_ERR_SHORT = -2,
    CLEANJSON_ERR_MAGIC = -3
};

typedef struct {
    uint32_t count;
    uint32_t sum;
} cleanjson_result;

int cleanjson_parse(const uint8_t *data, size_t size, cleanjson_result *out);

#endif /* CLEANJSON_H */

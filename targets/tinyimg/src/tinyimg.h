#ifndef TINYIMG_H
#define TINYIMG_H

#include <stddef.h>
#include <stdint.h>

enum {
    TINYIMG_OK          =  0,
    TINYIMG_ERR_ARG     = -1,
    TINYIMG_ERR_SHORT   = -2,
    TINYIMG_ERR_MAGIC   = -3,
    TINYIMG_ERR_VERSION = -4
};

typedef struct {
    uint8_t version;
    uint8_t n_channels;
    uint8_t first_id;
} tinyimg_info;

int tinyimg_parse(const uint8_t *data, size_t size, tinyimg_info *out);

#endif /* TINYIMG_H */

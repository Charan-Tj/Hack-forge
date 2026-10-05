#ifndef URLPARSE_H
#define URLPARSE_H
#include <stddef.h>
#include <stdint.h>

enum {
    URLPARSE_OK        =  0,
    URLPARSE_ERR_ARG   = -1,
    URLPARSE_ERR_SHORT = -2,
    URLPARSE_ERR_SCHEME = -3
};

typedef struct {
    uint16_t host_len;
    char     scheme[8];
    char     host[32];   /* last member: an overflow lands in the ASan redzone */
} urlinfo;

/* Parse "scheme://host[/...]" from a length-delimited buffer. */
int urlparse(const uint8_t *data, size_t size, urlinfo *out);

#endif

#ifndef SIGPKT_H
#define SIGPKT_H
#include <stddef.h>
#include <stdint.h>

enum {
    SIGPKT_OK         =  0,
    SIGPKT_ERR_ARG    = -1,
    SIGPKT_ERR_SHORT  = -2,
    SIGPKT_ERR_MAGIC  = -3,
    SIGPKT_ERR_DIGEST = -4
};

typedef struct {
    uint8_t  n_fields;
    uint32_t digest;
    uint16_t first_value;
} sigpkt_info;

#define SIGPKT_DIGEST_KEY 0xA5A5A5A5u

/* FNV-1a over `len` bytes. */
uint32_t sigpkt_fnv1a(const uint8_t *p, size_t len);
int sigpkt_parse(const uint8_t *data, size_t size, sigpkt_info *out);

#endif

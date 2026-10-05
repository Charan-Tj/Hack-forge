/* Regression test for sigpkt. Must pass before AND after any patch. */
#include "sigpkt.h"
#include <stdio.h>
#include <string.h>

static int check(const char *name, int cond) {
    if (!cond) { printf("FAIL: %s\n", name); return 1; }
    printf("ok: %s\n", name); return 0;
}

static void seal(uint8_t *pkt, uint8_t n_fields) {
    size_t body_len = (size_t)n_fields * 2;
    uint32_t d = sigpkt_fnv1a(pkt + 9, body_len) ^ SIGPKT_DIGEST_KEY;
    pkt[4] = n_fields;
    pkt[5] = d & 0xff; pkt[6] = (d >> 8) & 0xff;
    pkt[7] = (d >> 16) & 0xff; pkt[8] = (d >> 24) & 0xff;
}

int main(void) {
    int fails = 0;
    sigpkt_info s;

    /* valid: 2 fields */
    uint8_t p[9 + 64];
    memcpy(p, "SPK1", 4);
    p[9] = 0x11; p[10] = 0x00; p[11] = 0x22; p[12] = 0x00;
    seal(p, 2);
    int rc = sigpkt_parse(p, 9 + 4, &s);
    fails += check("valid parse OK", rc == SIGPKT_OK);
    fails += check("valid n_fields", s.n_fields == 2);
    fails += check("valid first_value", s.first_value == 0x11);

    /* valid: 32 fields (boundary, legal) */
    uint8_t q[9 + 64];
    memcpy(q, "SPK1", 4);
    for (int i = 0; i < 64; i++) q[9 + i] = (uint8_t)i;
    seal(q, 32);
    fails += check("32 fields OK", sigpkt_parse(q, 9 + 64, &s) == SIGPKT_OK);

    /* zero fields */
    uint8_t z[9];
    memcpy(z, "SPK1", 4);
    seal(z, 0);
    fails += check("zero fields OK", sigpkt_parse(z, 9, &s) == SIGPKT_OK);

    /* bad magic */
    uint8_t bm[9 + 4];
    memcpy(bm, "SPK0", 4); bm[9] = 1; bm[10] = 0; bm[11] = 2; bm[12] = 0; seal(bm, 2); bm[0] = 'X';
    fails += check("bad magic rejected", sigpkt_parse(bm, 9 + 4, &s) == SIGPKT_ERR_MAGIC);

    /* bad digest */
    uint8_t bd[9 + 4];
    memcpy(bd, "SPK1", 4); bd[9] = 1; bd[10] = 0; bd[11] = 2; bd[12] = 0; seal(bd, 2); bd[5] ^= 0xff;
    fails += check("bad digest rejected", sigpkt_parse(bd, 9 + 4, &s) == SIGPKT_ERR_DIGEST);

    if (fails == 0) printf("ALL TESTS PASSED\n");
    else            printf("%d TEST(S) FAILED\n", fails);
    return fails;
}

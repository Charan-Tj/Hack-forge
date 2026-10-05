/* Regression test for tinyimg. Must pass before AND after any patch.
 * Returns 0 on success, non-zero on failure. */
#include "tinyimg.h"
#include <stdio.h>
#include <string.h>

static int check(const char *name, int cond) {
    if (!cond) { printf("FAIL: %s\n", name); return 1; }
    printf("ok: %s\n", name);
    return 0;
}

int main(void) {
    int fails = 0;
    tinyimg_info info;

    /* valid: 2 channels */
    uint8_t good[] = { 'T','I','M','G', 1, 2,  10,8,  20,8 };
    int r = tinyimg_parse(good, sizeof(good), &info);
    fails += check("valid parse returns OK", r == TINYIMG_OK);
    fails += check("valid parse n_channels", info.n_channels == 2);
    fails += check("valid parse first_id", info.first_id == 10);

    /* valid: zero channels */
    uint8_t zero[] = { 'T','I','M','G', 1, 0 };
    fails += check("zero channels OK", tinyimg_parse(zero, sizeof(zero), &info) == TINYIMG_OK);

    /* valid: exactly 16 channels (boundary, legal) */
    uint8_t full[6 + 16*2];
    memcpy(full, "TIMG", 4); full[4] = 1; full[5] = 16;
    for (int i = 0; i < 16; i++) { full[6+i*2] = (uint8_t)i; full[6+i*2+1] = 8; }
    fails += check("16 channels OK", tinyimg_parse(full, sizeof(full), &info) == TINYIMG_OK);

    /* bad magic rejected */
    uint8_t badm[] = { 'X','I','M','G', 1, 1, 0,0 };
    fails += check("bad magic rejected", tinyimg_parse(badm, sizeof(badm), &info) == TINYIMG_ERR_MAGIC);

    /* truncated rejected */
    uint8_t shortb[] = { 'T','I','M','G' };
    fails += check("short rejected", tinyimg_parse(shortb, sizeof(shortb), &info) == TINYIMG_ERR_SHORT);

    if (fails == 0) printf("ALL TESTS PASSED\n");
    else            printf("%d TEST(S) FAILED\n", fails);
    return fails;
}

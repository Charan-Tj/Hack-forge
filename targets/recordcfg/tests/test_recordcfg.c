/* Regression test for recordcfg. Must pass before AND after any patch. */
#include "recordcfg.h"
#include <stdio.h>
#include <string.h>

static int check(const char *name, int cond) {
    if (!cond) { printf("FAIL: %s\n", name); return 1; }
    printf("ok: %s\n", name);
    return 0;
}

int main(void) {
    int fails = 0;
    recordcfg_summary s;

    /* valid: two short records (len 3 and len 5) */
    uint8_t good[] = {
        'R','C','F','1', 2,
        1, 3, 'a','b','c',
        2, 5, 'h','e','l','l','o'
    };
    int r = recordcfg_parse(good, sizeof(good), &s);
    fails += check("valid parse OK", r == RECORDCFG_OK);
    fails += check("valid n_records", s.n_records == 2);
    fails += check("valid total bytes", s.total_value_bytes == 8);

    /* valid: record of exactly 32 bytes (boundary, legal) */
    uint8_t full[5 + 2 + 32];
    memcpy(full, "RCF1", 4); full[4] = 1; full[5] = 7; full[6] = 32;
    for (int i = 0; i < 32; i++) full[7+i] = (uint8_t)i;
    fails += check("32-byte value OK", recordcfg_parse(full, sizeof(full), &s) == RECORDCFG_OK);

    /* zero records */
    uint8_t zero[] = { 'R','C','F','1', 0 };
    fails += check("zero records OK", recordcfg_parse(zero, sizeof(zero), &s) == RECORDCFG_OK);

    /* bad magic */
    uint8_t badm[] = { 'R','C','F','0', 0 };
    fails += check("bad magic rejected", recordcfg_parse(badm, sizeof(badm), &s) == RECORDCFG_ERR_MAGIC);

    /* truncated value */
    uint8_t trunc[] = { 'R','C','F','1', 1, 1, 9, 'x' };
    fails += check("truncated rejected", recordcfg_parse(trunc, sizeof(trunc), &s) == RECORDCFG_ERR_SHORT);

    if (fails == 0) printf("ALL TESTS PASSED\n");
    else            printf("%d TEST(S) FAILED\n", fails);
    return fails;
}

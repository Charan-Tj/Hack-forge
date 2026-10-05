/* Regression test for cleanjson. */
#include "cleanjson.h"
#include <stdio.h>

static int check(const char *name, int cond) {
    if (!cond) { printf("FAIL: %s\n", name); return 1; }
    printf("ok: %s\n", name);
    return 0;
}

int main(void) {
    int fails = 0;
    cleanjson_result r;

    uint8_t good[] = { 'C','J','S','N', 3, 10, 20, 30 };
    fails += check("valid OK", cleanjson_parse(good, sizeof(good), &r) == CLEANJSON_OK);
    fails += check("valid count", r.count == 3);
    fails += check("valid sum", r.sum == 60);

    /* count larger than available bytes is clamped safely */
    uint8_t over[] = { 'C','J','S','N', 200, 1, 2 };
    fails += check("over-count clamped", cleanjson_parse(over, sizeof(over), &r) == CLEANJSON_OK);
    fails += check("over-count seen", r.count == 2);

    uint8_t badm[] = { 'X','J','S','N', 0 };
    fails += check("bad magic rejected", cleanjson_parse(badm, sizeof(badm), &r) == CLEANJSON_ERR_MAGIC);

    if (fails == 0) printf("ALL TESTS PASSED\n");
    else            printf("%d TEST(S) FAILED\n", fails);
    return fails;
}

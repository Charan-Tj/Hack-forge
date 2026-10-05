/* Regression test for urlparse. Must pass before AND after any patch. */
#include "urlparse.h"
#include <stdio.h>
#include <string.h>

static int check(const char *name, int cond) {
    if (!cond) { printf("FAIL: %s\n", name); return 1; }
    printf("ok: %s\n", name); return 0;
}

int main(void) {
    int fails = 0;
    urlinfo u;

    const char *a = "http://example.com/path";
    int rc = urlparse((const uint8_t *)a, strlen(a), &u);
    fails += check("valid parse OK", rc == URLPARSE_OK);
    fails += check("scheme", strcmp(u.scheme, "http") == 0);
    fails += check("host", strcmp(u.host, "example.com") == 0);

    const char *b = "ftp://h/";
    fails += check("short host OK", urlparse((const uint8_t *)b, strlen(b), &u) == URLPARSE_OK);

    /* 31-char host (boundary, legal) */
    const char *c = "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/";
    fails += check("31-char host OK", urlparse((const uint8_t *)c, strlen(c), &u) == URLPARSE_OK);

    const char *d = "noscheme";
    fails += check("bad scheme rejected", urlparse((const uint8_t *)d, strlen(d), &u) == URLPARSE_ERR_SCHEME);

    if (fails == 0) printf("ALL TESTS PASSED\n");
    else            printf("%d TEST(S) FAILED\n", fails);
    return fails;
}

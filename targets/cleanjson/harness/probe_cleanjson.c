/* Behaviour probe for the differential gate (G5). Not part of the patch scope. */
#include "cleanjson.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb"); if (!f) return 2;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(n > 0 ? (size_t)n : 1); size_t got = fread(buf, 1, (size_t)n, f); fclose(f);
    cleanjson_result r = {0};
    int rc = cleanjson_parse(buf, got, &r);
    printf("rc=%d count=%u sum=%u\n", rc, rc == 0 ? r.count : 0, rc == 0 ? r.sum : 0);
    free(buf);
    return 0;
}

/* Behaviour probe for the differential gate (G5). Not part of the patch scope. */
#include "recordcfg.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb"); if (!f) return 2;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(n > 0 ? (size_t)n : 1); size_t got = fread(buf, 1, (size_t)n, f); fclose(f);
    recordcfg_summary s = {0};
    int rc = recordcfg_parse(buf, got, &s);
    printf("rc=%d n_records=%u total=%u\n", rc, rc == 0 ? s.n_records : 0, rc == 0 ? s.total_value_bytes : 0);
    free(buf);
    return 0;
}

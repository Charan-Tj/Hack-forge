/* Behaviour probe: prints the parser's observable result for one input file.
 * Used by KavachForge's differential gate (G5) to compare unpatched vs patched
 * behaviour across the whole corpus. Not part of the patch scope. */
#include "tinyimg.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb"); if (!f) return 2;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(n > 0 ? (size_t)n : 1); size_t got = fread(buf, 1, (size_t)n, f); fclose(f);
    tinyimg_info info = {0};
    int rc = tinyimg_parse(buf, got, &info);
    printf("rc=%d version=%u n_channels=%u first_id=%u\n", rc,
           rc == 0 ? info.version : 0, rc == 0 ? info.n_channels : 0, rc == 0 ? info.first_id : 0);
    free(buf);
    return 0;
}

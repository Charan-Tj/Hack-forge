/*
 * KavachForge standalone harness driver.
 *
 * Lets a libFuzzer-style harness (one that defines LLVMFuzzerTestOneInput)
 * run WITHOUT the libFuzzer runtime, so discovery works on any toolchain
 * that only provides AddressSanitizer (e.g. gcc + libasan). The KavachForge
 * discovery engine drives mutation in Python and invokes this binary once
 * per candidate input:
 *
 *     ./driver <input-file>
 *
 * The file is read into memory and passed to LLVMFuzzerTestOneInput exactly
 * once. If the input triggers a sanitizer error the process aborts with the
 * sanitizer's report on stderr and a non-zero exit code, which the engine
 * records as a crash for that input. A clean input exits 0.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* Provided by the target harness. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Optional one-time initializer some harnesses define; call if present. */
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char **argv) {
    if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(&argc, &argv);
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    if (n < 0) { fclose(f); return 2; }
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
    if (!buf) { fclose(f); return 2; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);

    LLVMFuzzerTestOneInput(buf, got);

    free(buf);
    return 0;
}

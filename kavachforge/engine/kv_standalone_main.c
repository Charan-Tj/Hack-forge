/*
 * KavachForge standalone harness driver (coverage-aware).
 *
 * Lets a libFuzzer-style harness (one that defines LLVMFuzzerTestOneInput)
 * run WITHOUT the libFuzzer runtime, so discovery works on any toolchain
 * that only provides AddressSanitizer (gcc+libasan, Apple clang, ...).
 *
 *     ./driver <input-file>
 *
 * The file is passed to LLVMFuzzerTestOneInput exactly once. A sanitizer
 * fault aborts the process with the report on stderr (non-zero exit); a
 * clean input exits 0.
 *
 * Coverage feedback: when the target is compiled with SanitizerCoverage
 * (-fsanitize-coverage=trace-pc-guard on clang, -fsanitize-coverage=trace-pc
 * on gcc), the callbacks below record executed edges into a 64 KiB bitmap.
 * If KV_COV_OUT is set, the bitmap is written there after a clean run, and
 * the Python engine uses "new edges" to grow its corpus (greybox fuzzing).
 * Without coverage instrumentation the callbacks are simply never called.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

#define KV_MAP_SIZE (1u << 16)
static uint8_t kv_cov_map[KV_MAP_SIZE];
static uint32_t kv_guard_count = 0;
static uintptr_t kv_prev = 0;

/* The coverage callbacks must NOT themselves be coverage-instrumented, or a
 * compiler that instruments every function (gcc's -fsanitize-coverage=trace-pc)
 * makes them call themselves on every edge -> infinite recursion -> stack
 * overflow. Exclude them explicitly (clang and gcc spell the attribute
 * differently). */
#if defined(__clang__)
#define KV_NOCOV __attribute__((no_sanitize("coverage")))
#elif defined(__GNUC__) && (__GNUC__ >= 12)
#define KV_NOCOV __attribute__((no_sanitize_coverage))
#else
#define KV_NOCOV
#endif

/* clang: one guard per edge, numbered at init. */
KV_NOCOV void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    if (start == stop || *start) return;
    for (uint32_t *g = start; g < stop; g++) *g = ++kv_guard_count;
}
KV_NOCOV void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    uint32_t id = *guard;
    if (!id) return;
    kv_cov_map[id & (KV_MAP_SIZE - 1)] = 1;
}

/* gcc: raw PC per edge; hash (prev,cur) AFL-style. */
KV_NOCOV void __sanitizer_cov_trace_pc(void) {
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    uintptr_t h = (pc >> 4) ^ (kv_prev << 1);
    kv_cov_map[h & (KV_MAP_SIZE - 1)] = 1;
    kv_prev = pc >> 4;
}

static void kv_dump_cov(void) {
    const char *out = getenv("KV_COV_OUT");
    if (!out || !*out) return;
    FILE *f = fopen(out, "wb");
    if (!f) return;
    fwrite(kv_cov_map, 1, KV_MAP_SIZE, f);
    fclose(f);
}

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

    memset(kv_cov_map, 0, sizeof(kv_cov_map));
    LLVMFuzzerTestOneInput(buf, got);
    kv_dump_cov();

    free(buf);
    return 0;
}

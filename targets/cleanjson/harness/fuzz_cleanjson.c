/* libFuzzer harness for cleanjson. */
#include "cleanjson.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cleanjson_result r;
    cleanjson_parse(data, size, &r);
    return 0;
}

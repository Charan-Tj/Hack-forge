/* libFuzzer harness for tinyimg. Do not edit as part of patching. */
#include "tinyimg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    tinyimg_info info;
    tinyimg_parse(data, size, &info);
    return 0;
}

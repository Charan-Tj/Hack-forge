/* libFuzzer harness for recordcfg. Do not edit as part of patching. */
#include "recordcfg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    recordcfg_summary s;
    recordcfg_parse(data, size, &s);
    return 0;
}

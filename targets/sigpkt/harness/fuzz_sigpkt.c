/* libFuzzer harness for sigpkt. Do not edit as part of patching. */
#include "sigpkt.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    sigpkt_info info;
    sigpkt_parse(data, size, &info);
    return 0;
}

#include <stdint.h>
#include <stddef.h>
#include "urlparse.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    urlinfo out;
    urlparse(data, size, &out);
    return 0;
}

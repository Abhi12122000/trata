#include <stddef.h>
#include <stdint.h>

void vulnerable_copy(const char *input);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char buffer[256] = {0};
    size_t to_copy = size < sizeof(buffer) - 1 ? size : sizeof(buffer) - 1;
    for (size_t i = 0; i < to_copy; ++i) {
        buffer[i] = (char)data[i];
    }
    vulnerable_copy(buffer);
    return 0;
}


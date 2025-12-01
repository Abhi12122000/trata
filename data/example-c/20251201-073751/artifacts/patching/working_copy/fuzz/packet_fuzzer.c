/*
 * libFuzzer harness focused on packet processing
 *
 * This harness specifically targets the process_packet() function
 * which has a heap buffer overflow that's hard for static analysis.
 *
 * NOTE: This file does NOT define main(). libFuzzer provides main().
 */

#include <stddef.h>
#include <stdint.h>

/* Include the header for function declarations */
#include "../src/vuln.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Directly fuzz the packet processor */
    process_packet(data, size);
    return 0;
}


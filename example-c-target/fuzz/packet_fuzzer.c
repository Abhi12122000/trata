/*
 * libFuzzer harness focused on packet processing
 *
 * This harness specifically targets the process_incoming_packet() function
 * which handles network protocol parsing with multiple code paths.
 *
 * NOTE: This file does NOT define main(). libFuzzer provides main().
 */

#include <stddef.h>
#include <stdint.h>

/* Include the header for function declarations */
#include "../src/vuln.h"

/* Initialize once at startup */
__attribute__((constructor))
static void init_fuzzer(void) {
    init_network_layer();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Directly fuzz the packet processor */
    process_incoming_packet(data, size);
    return 0;
}

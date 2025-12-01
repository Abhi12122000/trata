/*
 * Standalone main() for testing vuln.c manually.
 * 
 * This file is NOT compiled when building the fuzzer.
 * The fuzzer uses fuzz/vuln_fuzzer.c instead.
 */

#include <stdio.h>
#include <string.h>
#include "vuln.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <test>\n", argv[0]);
        printf("Tests: uaf, null, double, packet, resize, log\n");
        return 1;
    }

    if (strcmp(argv[1], "uaf") == 0) {
        use_after_free_example();
    } else if (strcmp(argv[1], "null") == 0) {
        null_deref_example(0);
    } else if (strcmp(argv[1], "double") == 0) {
        double_free_example();
    } else if (strcmp(argv[1], "packet") == 0) {
        // Test packet processing with crafted input
        uint8_t bad_packet[] = {0x00, 0xFF, 0xDE, 0xAD, 'A', 'B', 'C'};
        process_packet(bad_packet, sizeof(bad_packet));
    } else if (strcmp(argv[1], "resize") == 0) {
        // Test integer overflow
        uint8_t overflow_input[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01};
        resize_buffer(overflow_input, sizeof(overflow_input));
    } else if (strcmp(argv[1], "log") == 0) {
        // Test format string bug
        uint8_t fmt_input[] = {0x01, '%', 's', '%', 's', '%', 's', '%', 'n'};
        log_message(fmt_input, sizeof(fmt_input));
    } else {
        printf("Unknown test: %s\n", argv[1]);
        return 1;
    }

    return 0;
}


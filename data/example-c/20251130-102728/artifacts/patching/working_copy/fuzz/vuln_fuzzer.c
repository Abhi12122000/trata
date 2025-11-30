/*
 * libFuzzer harness for example-c-target
 *
 * This harness exercises all vulnerable functions in src/vuln.c.
 * The first byte of input selects which vulnerability to trigger,
 * and subsequent bytes provide parameters.
 *
 * NOTE: This file does NOT define main(). libFuzzer provides main().
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Include the header for function declarations */
#include "../src/vuln.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    /* Use first byte to select which bug to trigger */
    int choice = data[0] % 6;  /* 6 different bug types */

    switch (choice) {
        case 0:
            /* Trigger use-after-free */
            use_after_free_example();
            break;
            
        case 1:
            /* Trigger null dereference - pass second byte as trigger param */
            null_deref_example(size > 1 ? (int)data[1] : 0);
            break;
            
        case 2:
            /* Trigger double-free */
            double_free_example();
            break;
            
        case 3:
            /* Trigger packet processing bug (heap overflow) */
            /* Pass remaining data after choice byte */
            if (size > 1) {
                process_packet(data + 1, size - 1);
            }
            break;
            
        case 4:
            /* Trigger integer overflow in resize */
            if (size > 1) {
                resize_buffer(data + 1, size - 1);
            }
            break;
            
        case 5:
            /* Trigger format string / log bug */
            if (size > 1) {
                log_message(data + 1, size - 1);
            }
            break;
    }

    return 0;
}

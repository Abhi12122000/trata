/*
 * libFuzzer harness for example-c-target
 *
 * This harness exercises the vulnerable functions in src/vuln.c.
 * The first byte of input selects which vulnerability to trigger,
 * and subsequent bytes provide parameters.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Declarations from vuln.c */
void use_after_free_example(void);
void null_deref_example(int trigger);
void double_free_example(void);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    /* Use first byte to select which bug to trigger */
    int choice = data[0] % 3;

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
    }

    return 0;
}

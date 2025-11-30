#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Bug 1: Use-after-free
void use_after_free_example(void) {
    char *ptr = malloc(64);
    if (!ptr) return;
    strcpy(ptr, "hello");
    free(ptr);
    // BUG: accessing freed memory
    printf("Value: %s\n", ptr);
}

// Bug 2: Null dereference
void null_deref_example(int trigger) {
    char *ptr = NULL;
    if (trigger) {
        ptr = malloc(16);
    }
    // BUG: ptr might be NULL if trigger==0
    ptr[0] = 'A';
}

// Bug 3: Double free
void double_free_example(void) {
    char *ptr = malloc(32);
    free(ptr);
    // BUG: freeing already-freed memory
    free(ptr);
}

/* Only include main() when building standalone binary, not when fuzzing.
 * LibFuzzer provides its own main() that calls LLVMFuzzerTestOneInput. */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "uaf") == 0) {
        use_after_free_example();
    } else if (argc > 1 && strcmp(argv[1], "null") == 0) {
        null_deref_example(0);
    } else {
        double_free_example();
    }
    return 0;
}
#endif

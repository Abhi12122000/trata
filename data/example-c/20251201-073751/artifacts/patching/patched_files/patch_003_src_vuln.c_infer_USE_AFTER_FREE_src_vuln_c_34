/*
 * Vulnerable code examples for testing CRS.
 * 
 * This file contains various memory safety bugs:
 * - Some are detectable by static analysis (Infer)
 * - Some are only detectable by fuzzing (runtime)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vuln.h"

void use_after_free_example(void) {
    char *ptr = malloc(64);
    if (!ptr) return;
    strcpy(ptr, "hello");
    free(ptr);
    ptr = NULL;  // Prevent use-after-free by nullifying pointer
    // Removed use-after-free access
}

void null_deref_example(int trigger) {
    char *ptr = NULL;
    if (trigger) {
        ptr = malloc(16);
    }
    if (ptr) {
        free(ptr);
    }
    
    ptr[0] = 'A';
}

void double_free_example(void) {
    char *ptr = malloc(32);
    free(ptr);
    free(ptr);
}

/* ========================================================================
 * Bug 4: Heap buffer overflow (FUZZER ONLY - hard for static analysis)
 * 
 * This bug is triggered by specific input patterns that static analysis
 * cannot easily predict. The overflow depends on runtime data.
 * ======================================================================== */
void process_packet(const uint8_t *data, size_t size) {
    if (size < 4) return;
    
    // First 2 bytes: claimed length (can be malicious)
    uint16_t claimed_len = (data[0] << 8) | data[1];
    
    // Next 2 bytes: magic marker
    uint16_t magic = (data[2] << 8) | data[3];
    
    // Only process if magic is correct (fuzzer will find this)
    if (magic != 0xDEAD) return;
    
    // Allocate based on claimed length (attacker controlled)
    // BUG: No validation that claimed_len <= actual remaining data
    char *buffer = malloc(claimed_len);
    if (!buffer) return;
    
    // Copy remaining data - OVERFLOW if claimed_len > (size - 4)
    // Static analysis can't easily prove this is exploitable
    size_t remaining = size - 4;
    if (remaining > 0) {
        // BUG: memcpy uses claimed_len, not actual remaining size
        memcpy(buffer, data + 4, claimed_len);  // HEAP OVERFLOW HERE
    }
    
    buffer[0] = 'X';  // Use buffer to prevent optimization
    free(buffer);
}

/* ========================================================================
 * Bug 5: Integer overflow leading to small allocation (FUZZER ONLY)
 * 
 * This is a classic integer overflow bug that's hard for static analysis
 * because it requires specific input values.
 * ======================================================================== */
void resize_buffer(const uint8_t *data, size_t size) {
    if (size < 8) return;
    
    // Read two 32-bit values from input
    uint32_t width = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    uint32_t height = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    
    // Integer overflow check is missing!
    // If width * height overflows, we allocate a tiny buffer
    size_t alloc_size = width * height;  // BUG: can overflow on 32-bit or wrap
    
    if (alloc_size == 0) return;
    if (alloc_size > 1024 * 1024) return;  // "Safety" check bypassed by overflow
    
    char *pixels = malloc(alloc_size);
    if (!pixels) return;
    
    // Write beyond allocated buffer if overflow occurred
    // E.g., width=65536, height=65537 -> alloc_size wraps to 65536
    // but we try to access width*height bytes
    for (size_t i = 0; i < 100 && i < alloc_size; i++) {
        pixels[i] = 'P';
    }
    
    free(pixels);
}

/* ========================================================================
 * Bug 6: Stack buffer overflow via format string (FUZZER ONLY)
 * 
 * This requires specific input to trigger and is hard for static analysis
 * to prove exploitable without understanding the data flow.
 * ======================================================================== */
void log_message(const uint8_t *data, size_t size) {
    if (size < 2) return;
    
    // First byte is log level
    int level = data[0];
    if (level > 3) return;  // Only levels 0-3
    
    // Create message from remaining data
    char msg[64];
    size_t msg_len = size - 1;
    if (msg_len > 63) msg_len = 63;
    memcpy(msg, data + 1, msg_len);
    msg[msg_len] = '\0';
    
    // Stack buffer for formatted output
    char output[128];
    
    // BUG: If msg contains format specifiers, this can overflow
    // Static analysis may not catch this without taint tracking
    if (level == 0) {
        snprintf(output, sizeof(output), "[DEBUG] %s", msg);
    } else if (level == 1) {
        // BUG: Using msg directly as format string!
        snprintf(output, sizeof(output), msg);  // FORMAT STRING BUG
    } else {
        snprintf(output, sizeof(output), "[INFO] %s", msg);
    }
    
    // Use output to prevent optimization
    if (output[0]) {
        volatile char c = output[0];
        (void)c;
    }
}

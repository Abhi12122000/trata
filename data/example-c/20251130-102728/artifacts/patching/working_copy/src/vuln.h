/*
 * Header file for vuln.c - vulnerable code examples
 */

#ifndef VULN_H
#define VULN_H

#include <stddef.h>
#include <stdint.h>

/* Bugs detectable by both static analysis and fuzzing */
void use_after_free_example(void);
void null_deref_example(int trigger);
void double_free_example(void);

/* Bugs primarily detectable by fuzzing (hard for static analysis) */
void process_packet(const uint8_t *data, size_t size);
void resize_buffer(const uint8_t *data, size_t size);
void log_message(const uint8_t *data, size_t size);

#endif /* VULN_H */


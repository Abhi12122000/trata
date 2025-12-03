/*
 * libFuzzer harness for example-c-target
 *
 * This harness exercises the network utilities in src/vuln.c.
 * The first byte of input selects which function path to exercise,
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

/* Initialize once at startup */
__attribute__((constructor))
static void init_fuzzer(void) {
    init_network_layer();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    /* Use first byte to select which code path to exercise */
    int choice = data[0] % 8;
    const uint8_t *payload = data + 1;
    size_t payload_size = size > 1 ? size - 1 : 0;

    switch (choice) {
        case 0:
            /* Exercise packet processing */
            if (payload_size > 0) {
                process_incoming_packet(payload, payload_size);
            }
            break;
            
        case 1: {
            /* Exercise session creation and destruction */
            if (payload_size > 0 && payload_size < 64) {
                char username[64];
                memcpy(username, payload, payload_size);
                username[payload_size] = '\0';
                Session *s = create_session(username);
                if (s) {
                    /* Try updating session data */
                    if (payload_size > 4) {
                        update_session_data(s, payload + 4, payload_size - 4);
                    }
                    destroy_session(s);
                }
            }
            break;
        }
            
        case 2: {
            /* Exercise authentication */
            Session *s = create_session("fuzzuser");
            if (s && payload_size > 0) {
                authenticate_session(s, payload, payload_size);
                destroy_session(s);
            }
            break;
        }
            
        case 3: {
            /* Exercise base64 decoding */
            if (payload_size > 0 && payload_size < 256) {
                char input[256];
                memcpy(input, payload, payload_size);
                input[payload_size] = '\0';
                
                uint8_t output[256];
                size_t output_len = sizeof(output);
                decode_base64(input, output, &output_len);
            }
            break;
        }
            
        case 4: {
            /* Exercise compression */
            if (payload_size > 0) {
                uint8_t output[512];
                size_t output_len = sizeof(output);
                compress_data(payload, payload_size, output, &output_len);
            }
            break;
        }
            
        case 5: {
            /* Exercise string buffer operations */
            StringBuffer *sb = string_buffer_new(16);
            if (sb && payload_size > 0) {
                char str[128];
                size_t copy_len = payload_size < 127 ? payload_size : 127;
                memcpy(str, payload, copy_len);
                str[copy_len] = '\0';
                
                string_buffer_append(sb, str);
                string_buffer_append(sb, " - appended");
                
                StringBuffer *sb2 = string_buffer_new(16);
                if (sb2) {
                    string_buffer_copy(sb2, sb);
                    string_buffer_free(sb2);
                }
                
                string_buffer_free(sb);
            }
            break;
        }
            
        case 6: {
            /* Exercise logging with user input */
            if (payload_size >= 2) {
                int level = payload[0] % 4;
                char msg[128];
                size_t msg_len = payload_size - 1;
                if (msg_len > 127) msg_len = 127;
                memcpy(msg, payload + 1, msg_len);
                msg[msg_len] = '\0';
                log_event(level, "%s", msg);
            }
            break;
        }
            
        case 7: {
            /* Exercise packet hex logging */
            if (payload_size > 0) {
                log_packet_hex(payload, payload_size);
            }
            break;
        }
    }

    return 0;
}

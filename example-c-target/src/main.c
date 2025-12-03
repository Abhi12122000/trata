/*
 * Standalone main() for testing the network utilities manually.
 * 
 * This file is NOT compiled when building the fuzzer.
 * The fuzzer uses fuzz/vuln_fuzzer.c instead.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln.h"

static void print_usage(const char *prog) {
    printf("Usage: %s <command> [args...]\n", prog);
    printf("\nCommands:\n");
    printf("  init          - Initialize network layer\n");
    printf("  session NAME  - Create a session with given username\n");
    printf("  packet HEX    - Process a hex-encoded packet\n");
    printf("  auth TOKEN    - Authenticate with hex token\n");
    printf("  base64 STR    - Decode base64 string\n");
    printf("  compress HEX  - Compress hex data\n");
    printf("  buffer        - Test string buffer operations\n");
    printf("  cleanup       - Cleanup network layer\n");
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max_len) return -1;
    
    for (size_t i = 0; i < len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + i*2, "%02x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return len / 2;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *cmd = argv[1];
    
    if (strcmp(cmd, "init") == 0) {
        if (init_network_layer() == 0) {
            printf("Network layer initialized\n");
        } else {
            printf("Failed to initialize\n");
            return 1;
        }
    }
    else if (strcmp(cmd, "session") == 0) {
        if (argc < 3) {
            printf("Usage: %s session <username>\n", argv[0]);
            return 1;
        }
        init_network_layer();
        Session *s = create_session(argv[2]);
        if (s) {
            printf("Created session %u for user '%s'\n", s->id, s->username);
            destroy_session(s);
        } else {
            printf("Failed to create session\n");
            return 1;
        }
    }
    else if (strcmp(cmd, "packet") == 0) {
        if (argc < 3) {
            printf("Usage: %s packet <hex>\n", argv[0]);
            return 1;
        }
        init_network_layer();
        uint8_t packet[1024];
        int pkt_len = hex_to_bytes(argv[2], packet, sizeof(packet));
        if (pkt_len < 0) {
            printf("Invalid hex input\n");
            return 1;
        }
        int result = process_incoming_packet(packet, pkt_len);
        printf("Packet processing result: %d\n", result);
        cleanup_network_layer();
    }
    else if (strcmp(cmd, "auth") == 0) {
        if (argc < 3) {
            printf("Usage: %s auth <hex-token>\n", argv[0]);
            return 1;
        }
        init_network_layer();
        Session *s = create_session("testuser");
        if (s) {
            uint8_t token[64];
            int tok_len = hex_to_bytes(argv[2], token, sizeof(token));
            if (tok_len < 0) {
                printf("Invalid hex token\n");
                destroy_session(s);
                return 1;
            }
            int auth_result = authenticate_session(s, token, tok_len);
            printf("Authentication result: %d\n", auth_result);
            destroy_session(s);
        }
        cleanup_network_layer();
    }
    else if (strcmp(cmd, "base64") == 0) {
        if (argc < 3) {
            printf("Usage: %s base64 <string>\n", argv[0]);
            return 1;
        }
        uint8_t output[256];
        size_t output_len = sizeof(output);
        if (decode_base64(argv[2], output, &output_len) == 0) {
            printf("Decoded %zu bytes\n", output_len);
            for (size_t i = 0; i < output_len; i++) {
                printf("%02X ", output[i]);
            }
            printf("\n");
        } else {
            printf("Decode failed\n");
            return 1;
        }
    }
    else if (strcmp(cmd, "compress") == 0) {
        if (argc < 3) {
            printf("Usage: %s compress <hex>\n", argv[0]);
            return 1;
        }
        uint8_t input[256], output[512];
        int in_len = hex_to_bytes(argv[2], input, sizeof(input));
        if (in_len < 0) {
            printf("Invalid hex input\n");
            return 1;
        }
        size_t out_len = sizeof(output);
        if (compress_data(input, in_len, output, &out_len) == 0) {
            printf("Compressed to %zu bytes\n", out_len);
        } else {
            printf("Compression failed\n");
            return 1;
        }
    }
    else if (strcmp(cmd, "buffer") == 0) {
        StringBuffer *sb = string_buffer_new(16);
        if (!sb) {
            printf("Failed to create buffer\n");
            return 1;
        }
        string_buffer_append(sb, "Hello, ");
        string_buffer_append(sb, "World!");
        char *str = string_buffer_to_cstring(sb);
        printf("Buffer contents: %s\n", str);
        string_buffer_free(sb);
    }
    else if (strcmp(cmd, "cleanup") == 0) {
        cleanup_network_layer();
        printf("Cleanup complete\n");
    }
    else {
        printf("Unknown command: %s\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}

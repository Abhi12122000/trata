/*
 * Network packet processor and data utilities implementation
 * Part of the example-c target project
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "vuln.h"

/* Global state */
static Session *g_sessions[MAX_CONNECTIONS];
static int g_initialized = 0;
static StringBuffer *g_log_buffer = NULL;

/* ========================================================================
 * Network Layer Implementation
 * ======================================================================== */

int init_network_layer(void) {
    if (g_initialized) return 0;
    
    memset(g_sessions, 0, sizeof(g_sessions));
    g_log_buffer = string_buffer_new(256);
    g_initialized = 1;
    return 0;
}

void cleanup_network_layer(void) {
    if (!g_initialized) return;
    
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_sessions[i]) {
            destroy_session(g_sessions[i]);
            g_sessions[i] = NULL;
        }
    }
    
    if (g_log_buffer) {
        string_buffer_free(g_log_buffer);
        g_log_buffer = NULL;
    }
    
    g_initialized = 0;
}

int process_incoming_packet(const uint8_t *data, size_t len) {
    if (!g_initialized || !data) return -1;
    if (len < sizeof(PacketHeader)) return -1;
    
    /* Parse header */
    PacketHeader *header = (PacketHeader *)data;
    
    /* 
     * BUG 1: Integer overflow in length validation
     * The payload_len field is attacker-controlled. Adding sizeof(PacketHeader)
     * can wrap around on 16-bit arithmetic before the comparison.
     * COMMENT: This allows bypassing the size check when payload_len is near 0xFFFF
     */
    uint16_t total_expected = sizeof(PacketHeader) + header->payload_len;
    if (len < total_expected) {
        return -1;  /* Seems safe, but total_expected can wrap */
    }
    
    /* Verify checksum (simplified) */
    uint16_t computed = 0;
    for (size_t i = 0; i < len; i++) {
        computed ^= data[i];
    }
    
    /* Process based on flags */
    if (header->flags & 0x01) {
        /* Echo mode - copy payload back */
        char response[128];
        
        /*
         * BUG 2: Stack buffer overflow
         * payload_len is not validated against response buffer size.
         * COMMENT: If payload_len > 128, this overflows the stack buffer.
         */
        memcpy(response, header->payload, header->payload_len);
        response[header->payload_len] = '\0';
        
        log_event(0, "Echo: %s", response);
    }
    
    if (header->flags & 0x02) {
        /* Create session from payload */
        if (header->payload_len > 0 && header->payload_len < 32) {
            char username[32];
            memcpy(username, header->payload, header->payload_len);
            username[header->payload_len] = '\0';
            
            Session *s = create_session(username);
            if (s) {
                /* Store session */
                for (int i = 0; i < MAX_CONNECTIONS; i++) {
                    if (!g_sessions[i]) {
                        g_sessions[i] = s;
                        break;
                    }
                }
            }
        }
    }
    
    if (header->flags & 0x04) {
        /* Transform payload in-place */
        transform_payload(header, header->flags >> 8);
    }
    
    return 0;
}

int send_response(uint32_t session_id, const char *msg) {
    if (!msg) return -1;
    
    /* Find session */
    Session *session = NULL;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_sessions[i] && g_sessions[i]->id == session_id) {
            session = g_sessions[i];
            break;
        }
    }
    
    if (!session || !session->active) return -1;
    
    /* Log the response */
    log_event(1, "Response to %s: %s", session->username, msg);
    
    return 0;
}

/* ========================================================================
 * Session Management Implementation
 * ======================================================================== */

static uint32_t g_next_session_id = 1;

Session *create_session(const char *username) {
    if (!username) return NULL;
    
    Session *s = calloc(1, sizeof(Session));
    if (!s) return NULL;
    
    s->id = g_next_session_id++;
    s->active = 1;
    
    /*
     * BUG 3: Buffer overflow in username copy
     * strncpy doesn't guarantee null termination, and the size check
     * uses strlen which could be manipulated.
     * COMMENT: If username is exactly 32 bytes with no null, username field won't be terminated.
     */
    strncpy(s->username, username, sizeof(s->username));
    /* Missing: s->username[sizeof(s->username)-1] = '\0'; */
    
    return s;
}

void destroy_session(Session *session) {
    if (!session) return;
    
    /*
     * BUG 4: Use-after-free setup
     * user_data is freed but the session struct containing the pointer
     * is not immediately zeroed. If session is accessed after this call
     * but before the caller frees it, user_data is a dangling pointer.
     * COMMENT: The user_data pointer becomes dangling after this free.
     */
    if (session->user_data) {
        free(session->user_data);
        /* Missing: session->user_data = NULL; */
    }
    
    session->active = 0;
    free(session);
}

int authenticate_session(Session *session, const uint8_t *token, size_t token_len) {
    if (!session || !token) return -1;
    
    /*
     * BUG 5: Out-of-bounds read
     * If token_len < SESSION_KEY_LEN, memcmp reads beyond token buffer.
     * COMMENT: No validation that token_len >= SESSION_KEY_LEN before comparison.
     */
    if (memcmp(session->session_key, token, SESSION_KEY_LEN) == 0) {
        session->active = 1;
        return 0;
    }
    
    return -1;
}

int update_session_data(Session *session, const void *data, size_t len) {
    if (!session) return -1;
    
    /* Reallocate if needed */
    if (len > session->data_size) {
        /*
         * BUG 6: Memory leak on realloc failure
         * If realloc fails, the original pointer is lost.
         * COMMENT: Should save old pointer before realloc.
         */
        void *new_data = realloc(session->user_data, len);
        if (!new_data) {
            return -1;
        }
        session->user_data = new_data;
        session->data_size = len;
    }
    
    if (data && len > 0) {
        memcpy(session->user_data, data, len);
    }
    
    return 0;
}

/* ========================================================================
 * String Buffer Implementation  
 * ======================================================================== */

StringBuffer *string_buffer_new(size_t initial_capacity) {
    StringBuffer *sb = malloc(sizeof(StringBuffer));
    if (!sb) return NULL;
    
    sb->capacity = initial_capacity > 0 ? initial_capacity : 16;
    sb->buffer = malloc(sb->capacity);
    if (!sb->buffer) {
        free(sb);
        return NULL;
    }
    
    sb->length = 0;
    sb->buffer[0] = '\0';
    sb->ref_count = 1;
    
    return sb;
}

void string_buffer_free(StringBuffer *sb) {
    if (!sb) return;
    
    sb->ref_count--;
    
    /*
     * BUG 7: Use-after-free via reference counting
     * If ref_count goes negative (e.g., double free call), we still free.
     * Also, the buffer is freed even if ref_count > 0 after decrement fails.
     * COMMENT: Incorrect reference counting - should check ref_count == 0, not <= 0.
     */
    if (sb->ref_count <= 0) {
        free(sb->buffer);
        free(sb);
    }
}

int string_buffer_append(StringBuffer *sb, const char *str) {
    if (!sb || !str) return -1;
    
    size_t str_len = strlen(str);
    size_t new_len = sb->length + str_len;
    
    /* Grow buffer if needed */
    if (new_len >= sb->capacity) {
        /*
         * BUG 8: Integer overflow in capacity calculation
         * new_capacity can overflow if new_len is very large.
         * COMMENT: new_capacity = new_len * 2 + 1 can wrap around to a small value.
         */
        size_t new_capacity = new_len * 2 + 1;
        char *new_buffer = realloc(sb->buffer, new_capacity);
        if (!new_buffer) return -1;
        
        sb->buffer = new_buffer;
        sb->capacity = new_capacity;
    }
    
    memcpy(sb->buffer + sb->length, str, str_len + 1);
    sb->length = new_len;
    
    return 0;
}

char *string_buffer_to_cstring(StringBuffer *sb) {
    if (!sb) return NULL;
    
    /*
     * BUG 9: Returns internal buffer without copy
     * Caller might free or modify this, corrupting the StringBuffer state.
     * COMMENT: Should return a copy, not the internal buffer directly.
     */
    return sb->buffer;
}

int string_buffer_copy(StringBuffer *dest, const StringBuffer *src) {
    if (!dest || !src) return -1;
    
    /* Clear destination */
    dest->length = 0;
    
    /*
     * BUG 10: NULL dereference if src->buffer is NULL
     * We don't check if src->buffer is valid before copying.
     * COMMENT: Missing NULL check on src->buffer.
     */
    return string_buffer_append(dest, src->buffer);
}

/* ========================================================================
 * Data Transformation Implementation
 * ======================================================================== */

int decode_base64(const char *input, uint8_t *output, size_t *output_len) {
    if (!input || !output || !output_len) return -1;
    
    static const char b64_table[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    size_t input_len = strlen(input);
    
    /*
     * BUG 11: Output buffer size not validated
     * Decoded output is ~3/4 of input size, but we don't check if output
     * buffer is large enough.
     * COMMENT: Missing validation that *output_len >= (input_len * 3 / 4).
     */
    
    size_t i = 0, j = 0;
    uint32_t accum = 0;
    int bits = 0;
    
    while (i < input_len) {
        char c = input[i++];
        if (c == '=') break;
        
        char *p = strchr(b64_table, c);
        if (!p) continue;  /* Skip invalid chars */
        
        accum = (accum << 6) | (p - b64_table);
        bits += 6;
        
        if (bits >= 8) {
            bits -= 8;
            output[j++] = (accum >> bits) & 0xFF;
        }
    }
    
    *output_len = j;
    return 0;
}

int compress_data(const uint8_t *input, size_t input_len, 
                  uint8_t *output, size_t *output_len) {
    if (!input || !output || !output_len) return -1;
    
    /* Simple RLE compression */
    size_t out_idx = 0;
    size_t max_out = *output_len;
    
    for (size_t i = 0; i < input_len; ) {
        uint8_t byte = input[i];
        size_t count = 1;
        
        while (i + count < input_len && 
               input[i + count] == byte && 
               count < 255) {
            count++;
        }
        
        /*
         * BUG 12: Output buffer overflow
         * We write 2 bytes per run but only check after writing.
         * COMMENT: Check should be (out_idx + 2 > max_out) BEFORE writing.
         */
        output[out_idx++] = (uint8_t)count;
        output[out_idx++] = byte;
        
        if (out_idx > max_out) {
            return -1;  /* Too late - already overflowed */
        }
        
        i += count;
    }
    
    *output_len = out_idx;
    return 0;
}

int transform_payload(PacketHeader *packet, int transform_type) {
    if (!packet) return -1;
    
    uint8_t *payload = packet->payload;
    size_t len = packet->payload_len;
    
    switch (transform_type) {
        case 0:  /* XOR with key */
            for (size_t i = 0; i < len; i++) {
                payload[i] ^= 0x42;
            }
            break;
            
        case 1:  /* Reverse bytes */
            for (size_t i = 0; i < len / 2; i++) {
                uint8_t tmp = payload[i];
                payload[i] = payload[len - 1 - i];
                payload[len - 1 - i] = tmp;
            }
            break;
            
        case 2: {
            /* Decompress in-place - DANGEROUS */
            /*
             * BUG 13: Heap buffer overflow during decompression
             * Decompressed data can be larger than the original payload buffer.
             * COMMENT: No bounds checking on write during decompression.
             */
            size_t read_idx = 0;
            size_t write_idx = 0;
            
            while (read_idx + 1 < len) {
                uint8_t count = payload[read_idx++];
                uint8_t byte = payload[read_idx++];
                
                for (uint8_t i = 0; i < count; i++) {
                    payload[write_idx++] = byte;  /* Can overflow payload buffer */
                }
            }
            packet->payload_len = write_idx;
            break;
        }
            
        default:
            return -1;
    }
    
    return 0;
}

/* ========================================================================
 * Logging Implementation
 * ======================================================================== */

void log_event(int level, const char *format, ...) {
    if (!format) return;
    
    char buffer[256];
    va_list args;
    
    va_start(args, format);
    
    /*
     * BUG 14: Format string vulnerability
     * If 'format' contains user-controlled data with format specifiers,
     * this can lead to info leak or arbitrary write.
     * COMMENT: format should be validated or use fixed format with %s for user data.
     */
    vsnprintf(buffer, sizeof(buffer), format, args);
    
    va_end(args);
    
    /* Append to global log buffer */
    if (g_log_buffer) {
        static const char *level_names[] = {"DEBUG", "INFO", "WARN", "ERROR"};
        const char *level_name = (level >= 0 && level < 4) ? level_names[level] : "UNKNOWN";
        
        char log_line[300];
        snprintf(log_line, sizeof(log_line), "[%s] %s\n", level_name, buffer);
        string_buffer_append(g_log_buffer, log_line);
    }
}

void log_packet_hex(const uint8_t *data, size_t len) {
    if (!data) return;
    
    char hex_output[64];
    
    for (size_t i = 0; i < len && i < 16; i++) {
        snprintf(hex_output + i*3, 4, "%02X ", data[i]);
    }
    
    log_event(0, "Packet: %s", hex_output);
}

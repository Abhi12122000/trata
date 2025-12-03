/*
 * Network packet processor and data utilities
 * Part of the example-c target project
 */

#ifndef VULN_H
#define VULN_H

#include <stddef.h>
#include <stdint.h>

/* Configuration constants */
#define MAX_PACKET_SIZE 4096
#define MAX_CONNECTIONS 64
#define SESSION_KEY_LEN 32

/* Data structures */
typedef struct {
    uint32_t id;
    uint32_t flags;
    uint16_t payload_len;
    uint16_t checksum;
    uint8_t payload[0];  /* Flexible array member */
} PacketHeader;

typedef struct {
    uint32_t id;
    int active;
    char username[32];
    uint8_t session_key[SESSION_KEY_LEN];
    void *user_data;
    size_t data_size;
} Session;

typedef struct {
    char *buffer;
    size_t capacity;
    size_t length;
    int ref_count;
} StringBuffer;

/* Network layer functions */
int init_network_layer(void);
void cleanup_network_layer(void);
int process_incoming_packet(const uint8_t *data, size_t len);
int send_response(uint32_t session_id, const char *msg);

/* Session management */
Session *create_session(const char *username);
void destroy_session(Session *session);
int authenticate_session(Session *session, const uint8_t *token, size_t token_len);
int update_session_data(Session *session, const void *data, size_t len);

/* String utilities */
StringBuffer *string_buffer_new(size_t initial_capacity);
void string_buffer_free(StringBuffer *sb);
int string_buffer_append(StringBuffer *sb, const char *str);
char *string_buffer_to_cstring(StringBuffer *sb);
int string_buffer_copy(StringBuffer *dest, const StringBuffer *src);

/* Data transformation */
int decode_base64(const char *input, uint8_t *output, size_t *output_len);
int compress_data(const uint8_t *input, size_t input_len, uint8_t *output, size_t *output_len);
int transform_payload(PacketHeader *packet, int transform_type);

/* Logging */
void log_event(int level, const char *format, ...);
void log_packet_hex(const uint8_t *data, size_t len);

#endif /* VULN_H */

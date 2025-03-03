#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Message header structure */
typedef struct {
    uint8_t type;          // Message type
    uint32_t length;       // Message length (excluding header)
    uint32_t padding_len;  // Length of random padding
    uint64_t timestamp;    // Message timestamp
} message_header_t;

/* Serialized message structure */
typedef struct {
    message_header_t header;
    unsigned char *data;   // Message data (dynamically allocated)
    size_t data_len;       // Length of data
} serialized_message_t;

/* Message serialization functions */
int serialize_text_message(const char *text, size_t text_len,
                          const char *username, size_t username_len,
                          serialized_message_t *message);

int serialize_ping_message(serialized_message_t *message);

int serialize_pong_message(serialized_message_t *message);

int serialize_ratchet_message(const unsigned char *ratchet_data, size_t ratchet_len,
                             serialized_message_t *message);

int serialize_dummy_message(serialized_message_t *message);

int serialize_disconnect_message(serialized_message_t *message);

/* Message deserialization functions */
int deserialize_message(const unsigned char *data, size_t data_len,
                       serialized_message_t *message);

int extract_text_message(const serialized_message_t *message,
                        char *text, size_t *text_len,
                        char *username, size_t *username_len);

int extract_ratchet_data(const serialized_message_t *message,
                        unsigned char *ratchet_data, size_t *ratchet_len);

/* Memory management */
void free_serialized_message(serialized_message_t *message);

#ifdef __cplusplus
}
#endif

#endif // SERIALIZATION_H

#include "../../include/serialization.h"
#include "../../include/common.h"
#include "../../include/crypto.h"  // Add this for add_random_padding function
#include <string.h>
#include <time.h>

/* Serialize a text message */
int serialize_text_message(const char *text, size_t text_len,
                          const char *username, size_t username_len,
                          serialized_message_t *message)
{
    if (!text || !username || !message) {
        return -1;
    }

    // Validate lengths
    if (text_len == 0 || username_len == 0 || username_len > USERNAME_SIZE) {
        return -1;
    }

    // Initialize the message header
    message->header.type = MSG_TYPE_TEXT;
    message->header.timestamp = (uint64_t)time(NULL);

    // Calculate the data size: username length (1 byte) + username + text
    size_t data_size = 1 + username_len + text_len;
    
    // Allocate memory for the data
    message->data = (unsigned char *)secure_alloc(data_size);
    if (!message->data) {
        return -1;
    }

    // Set the username length
    message->data[0] = (uint8_t)username_len;
    
    // Copy the username
    memcpy(message->data + 1, username, username_len);
    
    // Copy the text
    memcpy(message->data + 1 + username_len, text, text_len);
    
    // Set the data length
    message->data_len = data_size;
    message->header.length = data_size;
    
    // Add random padding
    size_t padded_size = add_random_padding(message->data, data_size, data_size + MAX_PADDING);
    message->data_len = padded_size;
    message->header.padding_len = padded_size - data_size;

    return 0;
}

/* Serialize a ping message */
int serialize_ping_message(serialized_message_t *message)
{
    if (!message) {
        return -1;
    }

    // Initialize the message header
    message->header.type = MSG_TYPE_PING;
    message->header.timestamp = (uint64_t)time(NULL);
    message->header.length = 0;
    
    // No data for ping message
    message->data = NULL;
    message->data_len = 0;
    message->header.padding_len = 0;

    return 0;
}

/* Serialize a pong message */
int serialize_pong_message(serialized_message_t *message)
{
    if (!message) {
        return -1;
    }

    // Initialize the message header
    message->header.type = MSG_TYPE_PONG;
    message->header.timestamp = (uint64_t)time(NULL);
    message->header.length = 0;
    
    // No data for pong message
    message->data = NULL;
    message->data_len = 0;
    message->header.padding_len = 0;

    return 0;
}

/* Serialize a ratchet message */
int serialize_ratchet_message(const unsigned char *ratchet_data, size_t ratchet_len,
                             serialized_message_t *message)
{
    if (!ratchet_data || !message) {
        return -1;
    }

    // Validate length
    if (ratchet_len == 0) {
        return -1;
    }

    // Initialize the message header
    message->header.type = MSG_TYPE_RATCHET;
    message->header.timestamp = (uint64_t)time(NULL);
    message->header.length = ratchet_len;
    
    // Allocate memory for the data
    message->data = (unsigned char *)secure_alloc(ratchet_len);
    if (!message->data) {
        return -1;
    }
    
    // Copy the ratchet data
    memcpy(message->data, ratchet_data, ratchet_len);
    
    // Set the data length
    message->data_len = ratchet_len;
    
    // Add random padding
    size_t padded_size = add_random_padding(message->data, ratchet_len, ratchet_len + MAX_PADDING);
    message->data_len = padded_size;
    message->header.padding_len = padded_size - ratchet_len;

    return 0;
}

/* Serialize a dummy message */
int serialize_dummy_message(serialized_message_t *message)
{
    if (!message) {
        return -1;
    }

    // Initialize the message header
    message->header.type = MSG_TYPE_DUMMY;
    message->header.timestamp = (uint64_t)time(NULL);
    
    // Generate random data for the dummy message
    size_t dummy_len = MIN_PADDING + randombytes_uniform(MAX_PADDING - MIN_PADDING);
    
    // Allocate memory for the data
    message->data = (unsigned char *)secure_alloc(dummy_len);
    if (!message->data) {
        return -1;
    }
    
    // Fill with random data
    randombytes_buf(message->data, dummy_len);
    
    // Set the data length
    message->data_len = dummy_len;
    message->header.length = dummy_len;
    message->header.padding_len = 0; // No additional padding for dummy messages

    return 0;
}

/* Serialize a disconnect message */
int serialize_disconnect_message(serialized_message_t *message)
{
    if (!message) {
        return -1;
    }

    // Initialize the message header
    message->header.type = MSG_TYPE_DISCONNECT;
    message->header.timestamp = (uint64_t)time(NULL);
    message->header.length = 0;
    
    // No data for disconnect message
    message->data = NULL;
    message->data_len = 0;
    message->header.padding_len = 0;

    return 0;
}

/* Deserialize a message */
int deserialize_message(const unsigned char *data, size_t data_len,
                       serialized_message_t *message)
{
    if (!data || !message || data_len < sizeof(message_header_t)) {
        return -1;
    }

    // Copy the header
    memcpy(&message->header, data, sizeof(message_header_t));
    
    // Validate the header
    if (message->header.length + message->header.padding_len > data_len - sizeof(message_header_t)) {
        return -1;
    }
    
    // Copy the data if present
    if (message->header.length + message->header.padding_len > 0) {
        message->data = (unsigned char *)secure_alloc(message->header.length + message->header.padding_len);
        if (!message->data) {
            return -1;
        }
        
        memcpy(message->data, data + sizeof(message_header_t), 
               message->header.length + message->header.padding_len);
        message->data_len = message->header.length + message->header.padding_len;
    } else {
        message->data = NULL;
        message->data_len = 0;
    }

    return 0;
}

/* Extract text message content */
int extract_text_message(const serialized_message_t *message,
                        char *text, size_t *text_len,
                        char *username, size_t *username_len)
{
    if (!message || !text || !text_len || !username || !username_len) {
        return -1;
    }

    // Validate message type
    if (message->header.type != MSG_TYPE_TEXT) {
        return -1;
    }
    
    // Validate data
    if (!message->data || message->data_len < 1) {
        return -1;
    }
    
    // Remove padding if present
    size_t actual_data_len = message->header.length;
    
    // Get the username length
    uint8_t uname_len = message->data[0];
    
    // Validate username length
    if (uname_len == 0 || uname_len > USERNAME_SIZE || uname_len >= actual_data_len) {
        return -1;
    }
    
    // Copy the username
    if (*username_len < uname_len) {
        return -1; // Buffer too small
    }
    memcpy(username, message->data + 1, uname_len);
    *username_len = uname_len;
    
    // Calculate text length
    size_t txt_len = actual_data_len - 1 - uname_len;
    
    // Copy the text
    if (*text_len < txt_len) {
        return -1; // Buffer too small
    }
    memcpy(text, message->data + 1 + uname_len, txt_len);
    *text_len = txt_len;

    return 0;
}

/* Extract ratchet data */
int extract_ratchet_data(const serialized_message_t *message,
                        unsigned char *ratchet_data, size_t *ratchet_len)
{
    if (!message || !ratchet_data || !ratchet_len) {
        return -1;
    }

    // Validate message type
    if (message->header.type != MSG_TYPE_RATCHET) {
        return -1;
    }
    
    // Validate data
    if (!message->data || message->data_len < message->header.length) {
        return -1;
    }
    
    // Check buffer size
    if (*ratchet_len < message->header.length) {
        return -1; // Buffer too small
    }
    
    // Copy the ratchet data
    memcpy(ratchet_data, message->data, message->header.length);
    *ratchet_len = message->header.length;

    return 0;
}

/* Free serialized message */
void free_serialized_message(serialized_message_t *message)
{
    if (message) {
        if (message->data) {
            secure_free(message->data);
            message->data = NULL;
        }
        message->data_len = 0;
    }
}

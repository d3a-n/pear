#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Key types */
typedef struct {
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];
} key_pair_t;

typedef struct {
    unsigned char key[KEY_SIZE];
} symmetric_key_t;

/* Ratchet state */
typedef struct {
    key_pair_t dh_pair;                // Current DH key pair
    key_pair_t remote_dh_pair;         // Remote DH public key
    symmetric_key_t root_key;          // Root key for the ratchet
    symmetric_key_t chain_key_send;    // Sending chain key
    symmetric_key_t chain_key_recv;    // Receiving chain key
    uint32_t send_count;               // Number of messages sent
    uint32_t recv_count;               // Number of messages received
    uint8_t initialized;               // Whether the ratchet is initialized
} ratchet_state_t;

/* Session keys */
typedef struct {
    symmetric_key_t tx_key;            // Transmit key
    symmetric_key_t rx_key;            // Receive key
    ratchet_state_t ratchet;           // Double ratchet state
} session_keys_t;

/* Triple Diffie-Hellman key exchange */
int perform_3dh_key_exchange(int sock,
                            const char *local_username,
                            char *remote_username,
                            session_keys_t *session_keys,
                            int is_server);

/* Double Ratchet functions */
int initialize_ratchet(ratchet_state_t *ratchet, 
                      const symmetric_key_t *shared_secret,
                      const key_pair_t *dh_pair,
                      const unsigned char *remote_public_key,
                      int is_sender);

int ratchet_encrypt(ratchet_state_t *ratchet,
                   const unsigned char *plaintext, size_t plaintext_len,
                   unsigned char *ciphertext, size_t *ciphertext_len);

int ratchet_decrypt(ratchet_state_t *ratchet,
                   const unsigned char *ciphertext, size_t ciphertext_len,
                   unsigned char *plaintext, size_t *plaintext_len);

/* Message encryption/decryption */
int encrypt_message(const unsigned char *plaintext, size_t plaintext_len,
                   const symmetric_key_t *key,
                   unsigned char *ciphertext, size_t *ciphertext_len);

int decrypt_message(const unsigned char *ciphertext, size_t ciphertext_len,
                   const symmetric_key_t *key,
                   unsigned char *plaintext, size_t *plaintext_len);

/* Key derivation */
int derive_keys(const unsigned char *input, size_t input_len,
               const unsigned char *salt, size_t salt_len,
               const unsigned char *info, size_t info_len,
               symmetric_key_t *output_key);

/* Random padding */
size_t add_random_padding(unsigned char *buffer, size_t content_len, size_t max_len);
size_t remove_padding(unsigned char *buffer, size_t buffer_len);

/* Secure memory handling */
void wipe_sensitive_data(void *data, size_t len);
void wipe_session_keys(session_keys_t *keys);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_H

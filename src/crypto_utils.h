#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "common.h"

/* ---------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 * --------------------------------------------------------------------------- */

/* Performs ephemeral key exchange using libsodium. */
int perform_key_exchange(int sock, 
                         const char *local_username,
                         char *remote_username,
                         unsigned char *rx_key,
                         unsigned char *tx_key,
                         int is_server);

/* Encrypts 'plaintext' into 'ciphertext' using ChaCha20-Poly1305 AEAD. */
int encrypt_message(const unsigned char *plaintext, 
                    size_t plaintext_len,
                    const unsigned char *key,
                    unsigned char *ciphertext,
                    size_t *ciphertext_len);

/* Decrypts 'ciphertext' into 'plaintext' using ChaCha20-Poly1305 AEAD. */
int decrypt_message(const unsigned char *ciphertext, 
                    size_t ciphertext_len,
                    const unsigned char *key,
                    unsigned char *plaintext, 
                    size_t *plaintext_len);

/* Securely zero out sensitive data. */
void secure_memzero(void *v, size_t n);

#endif // CRYPTO_UTILS_H
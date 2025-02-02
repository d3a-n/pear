#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "common.h"

// Performs an ephemeral key exchange using libsodium's crypto_kx API.
// On success, the session keys (rx_key and tx_key) are derived.
// Logs every step of the process.
int perform_key_exchange(int sock, const char *local_username, char *remote_username,
                         unsigned char *rx_key, unsigned char *tx_key, int is_server);

// Encrypts a message using ChaCha20-Poly1305 AEAD.
// The ciphertext buffer must be large enough to hold the nonce plus the ciphertext.
// Logs the encryption process.
int encrypt_message(const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char *key,
                    unsigned char *ciphertext, size_t *ciphertext_len);

// Decrypts a message using ChaCha20-Poly1305 AEAD.
// Logs the decryption process.
int decrypt_message(const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *key,
                    unsigned char *plaintext, size_t *plaintext_len);

// Securely zero out sensitive data using libsodium's sodium_memzero.
// Logs when sensitive data is cleared.
void secure_memzero(void *v, size_t n);

#endif // CRYPTO_UTILS_H
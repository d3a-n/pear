#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "common.h"

/*
 * Performs a dual Diffie-Hellman ephemeral key exchange.
 * Each side generates two ephemeral key pairs and computes:
 *   DH1 = crypto_scalarmult(local_eph1_sk, remote_pk1)
 *   DH2 = crypto_scalarmult(local_eph2_sk, remote_pk2)
 * The 64-byte concatenation of DH1 || DH2 is hashed (using crypto_generichash)
 * into a 32-byte master secret. Then:
 *   Server: rx_key = H(master_secret, "c2s"), tx_key = H(master_secret, "s2c")
 *   Client: tx_key = H(master_secret, "c2s"), rx_key = H(master_secret, "s2c")
 *
 * Returns 0 on success, -1 on error.
 */
int perform_key_exchange(int sock,
                         const char *local_username,
                         char *remote_username,
                         unsigned char *rx_key,
                         unsigned char *tx_key,
                         int is_server);

/*
 * Encrypts plaintext using ChaCha20-Poly1305 (IETF).
 * The output ciphertext = [nonce (12 bytes)] || [encrypted data + auth tag].
 * Returns 0 on success, -1 on error.
 */
int encrypt_message(const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char *key,
                    unsigned char *ciphertext, size_t *ciphertext_len);

/*
 * Decrypts ciphertext using ChaCha20-Poly1305 (IETF).
 * Assumes the first 12 bytes of ciphertext are the nonce.
 * Returns 0 on success, -1 on error.
 */
int decrypt_message(const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *key,
                    unsigned char *plaintext, size_t *plaintext_len);

/* Securely zero out memory. */
void secure_memzero(void *v, size_t n);

#endif // CRYPTO_UTILS_H
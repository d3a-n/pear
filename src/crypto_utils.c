#include "crypto_utils.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

// Helper function: read exactly 'length' bytes from the socket.
static ssize_t read_exact(int sock, void *buffer, size_t length) {
    size_t total = 0;
    unsigned char *buf = (unsigned char*)buffer;
    while (total < length) {
        ssize_t r = recv(sock, (char*)(buf + total), length - total, 0);
        if (r <= 0) {
            return -1;
        }
        total += r;
    }
    return (ssize_t)total;
}

int perform_key_exchange(int sock, const char *local_username, char *remote_username,
                         unsigned char *rx_key, unsigned char *tx_key, int is_server) {
    (void)local_username;
    (void)remote_username;
    
    unsigned char local_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char local_sk[crypto_kx_SECRETKEYBYTES];
    
    if (crypto_kx_keypair(local_pk, local_sk) != 0) {
        fprintf(stderr, "Key pair generation failed.\n");
        return -1;
    }
    
    if (send(sock, (const char*)local_pk, crypto_kx_PUBLICKEYBYTES, 0) < 0) {
        fprintf(stderr, "Failed to send local public key (errno=%d).\n", errno);
        secure_memzero(local_sk, sizeof(local_sk));
        return -1;
    }
    
    unsigned char remote_pk[crypto_kx_PUBLICKEYBYTES];
    ssize_t bytes_received = read_exact(sock, remote_pk, crypto_kx_PUBLICKEYBYTES);
    if (bytes_received < (ssize_t)crypto_kx_PUBLICKEYBYTES) {
        fprintf(stderr, "Failed to receive remote public key (received %zd bytes).\n", bytes_received);
        secure_memzero(local_sk, sizeof(local_sk));
        return -1;
    }
    
    int status;
    if (is_server) {
        status = crypto_kx_server_session_keys(rx_key, tx_key, local_pk, local_sk, remote_pk);
    } else {
        status = crypto_kx_client_session_keys(rx_key, tx_key, local_pk, local_sk, remote_pk);
    }
    secure_memzero(local_sk, sizeof(local_sk));
    if (status != 0) {
        fprintf(stderr, "Session key derivation failed.\n");
        return -1;
    }
    return 0;
}

int encrypt_message(const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char *key,
                    unsigned char *ciphertext, size_t *ciphertext_len) {
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    
    unsigned long long ct_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext + sizeof(nonce), &ct_len,
            plaintext, plaintext_len,
            NULL, 0,
            NULL,
            nonce, key) != 0) {
        fprintf(stderr, "Encryption failed.\n");
        return -1;
    }
    
    memcpy(ciphertext, nonce, sizeof(nonce));
    *ciphertext_len = ct_len + sizeof(nonce);
    return 0;
}

int decrypt_message(const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *key,
                    unsigned char *plaintext, size_t *plaintext_len) {
    if (ciphertext_len < crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
        return -1;
    
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    memcpy(nonce, ciphertext, sizeof(nonce));
    
    const unsigned char *enc_data = ciphertext + sizeof(nonce);
    size_t enc_data_len = ciphertext_len - sizeof(nonce);
    
    unsigned long long pt_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &pt_len,
            NULL,
            enc_data, enc_data_len,
            NULL, 0,
            nonce, key) != 0) {
        fprintf(stderr, "Decryption failed. Data may have been tampered with.\n");
        return -1;
    }
    *plaintext_len = (size_t)pt_len;
    return 0;
}

void secure_memzero(void *v, size_t n) {
    if (v && n > 0) {
        sodium_memzero(v, n);
    }
}

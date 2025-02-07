#include "crypto_utils.h"
#include <string.h>

#ifdef DEBUG_KEYS
static void debug_print_hex(const char *label, const unsigned char *data, size_t len) {
    fprintf(stderr, "%s: ", label);
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02X", data[i]);
    }
    fprintf(stderr, "\n");
}
#endif

static ssize_t read_exact(int sock, void *buffer, size_t length) {
    size_t total = 0;
    unsigned char *buf = (unsigned char *)buffer;
    while (total < length) {
        ssize_t r = recv(sock, (char *)(buf + total), length - total, 0);
        if (r <= 0) {
            if (r < 0 && (errno == EINTR || errno == EAGAIN))
                continue;
            return -1;
        }
        total += r;
    }
    return (ssize_t)total;
}

/* dual_dh: computes two DH operations and hashes them into a master secret */
static int dual_dh(const unsigned char *local_sk1, const unsigned char *local_sk2,
                   const unsigned char *remote_pk1, const unsigned char *remote_pk2,
                   unsigned char *master_secret)
{
    unsigned char dh1[crypto_scalarmult_BYTES];
    unsigned char dh2[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(dh1, local_sk1, remote_pk1) != 0) {
        LOG_ERROR("DH1 failed.");
        return -1;
    }
    if (crypto_scalarmult(dh2, local_sk2, remote_pk2) != 0) {
        LOG_ERROR("DH2 failed.");
        return -1;
    }

    unsigned char combined[crypto_scalarmult_BYTES * 2];
    memcpy(combined, dh1, crypto_scalarmult_BYTES);
    memcpy(combined + crypto_scalarmult_BYTES, dh2, crypto_scalarmult_BYTES);

    if (crypto_generichash(master_secret, 32, combined, sizeof(combined), NULL, 0) != 0) {
        LOG_ERROR("Failed to hash DH outputs.");
        return -1;
    }

    secure_memzero(dh1, sizeof(dh1));
    secure_memzero(dh2, sizeof(dh2));
    secure_memzero(combined, sizeof(combined));
    return 0;
}

int perform_key_exchange(int sock,
                         const char *local_username,
                         char *remote_username,
                         unsigned char *rx_key,
                         unsigned char *tx_key,
                         int is_server)
{
    (void)local_username;
    (void)remote_username;

    LOG_STEP("Generating two ephemeral key pairs...");
    unsigned char eph1_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char eph1_sk[crypto_box_SECRETKEYBYTES];
    if (crypto_box_keypair(eph1_pk, eph1_sk) != 0) {
        LOG_ERROR("Failed to generate ephemeral keypair #1.");
        return -1;
    }

    unsigned char eph2_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char eph2_sk[crypto_box_SECRETKEYBYTES];
    if (crypto_box_keypair(eph2_pk, eph2_sk) != 0) {
        LOG_ERROR("Failed to generate ephemeral keypair #2.");
        secure_memzero(eph1_sk, sizeof(eph1_sk));
        return -1;
    }

    LOG_STEP("Sending ephemeral public keys to peer...");
    unsigned char send_buffer[crypto_box_PUBLICKEYBYTES * 2];
    memcpy(send_buffer, eph1_pk, crypto_box_PUBLICKEYBYTES);
    memcpy(send_buffer + crypto_box_PUBLICKEYBYTES, eph2_pk, crypto_box_PUBLICKEYBYTES);
    if (send_all(sock, send_buffer, sizeof(send_buffer), 0) < 0) {
        LOG_ERROR("Failed to send ephemeral public keys.");
        goto fail;
    }

    LOG_STEP("Receiving ephemeral public keys from peer...");
    unsigned char recv_buffer[crypto_box_PUBLICKEYBYTES * 2];
    if (read_exact(sock, recv_buffer, sizeof(recv_buffer)) < (ssize_t)sizeof(recv_buffer)) {
        LOG_ERROR("Failed to receive remote ephemeral public keys.");
        goto fail;
    }
    unsigned char remote_pk1[crypto_box_PUBLICKEYBYTES];
    unsigned char remote_pk2[crypto_box_PUBLICKEYBYTES];
    memcpy(remote_pk1, recv_buffer, crypto_box_PUBLICKEYBYTES);
    memcpy(remote_pk2, recv_buffer + crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);

    LOG_STEP("Performing dual DH computations...");
    unsigned char master_secret[32];
    if (dual_dh(eph1_sk, eph2_sk, remote_pk1, remote_pk2, master_secret) != 0) {
        LOG_ERROR("Dual DH failed.");
        goto fail;
    }

    if (is_server) {
        crypto_generichash(rx_key, 32, master_secret, 32, (const unsigned char *)"c2s", 3);
        crypto_generichash(tx_key, 32, master_secret, 32, (const unsigned char *)"s2c", 3);
    } else {
        crypto_generichash(tx_key, 32, master_secret, 32, (const unsigned char *)"c2s", 3);
        crypto_generichash(rx_key, 32, master_secret, 32, (const unsigned char *)"s2c", 3);
    }

#ifdef DEBUG_KEYS
    debug_print_hex("rx_key", rx_key, 32);
    debug_print_hex("tx_key", tx_key, 32);
#endif

    secure_memzero(eph1_sk, sizeof(eph1_sk));
    secure_memzero(eph2_sk, sizeof(eph2_sk));
    secure_memzero(master_secret, sizeof(master_secret));
    return 0;
fail:
    secure_memzero(eph1_sk, sizeof(eph1_sk));
    secure_memzero(eph2_sk, sizeof(eph2_sk));
    return -1;
}

int encrypt_message(const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char *key,
                    unsigned char *ciphertext, size_t *ciphertext_len)
{
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned long long ct_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext + sizeof(nonce), &ct_len,
            plaintext, plaintext_len,
            NULL, 0,
            NULL,
            nonce, key) != 0)
    {
        LOG_ERROR("Encryption failed.");
        return -1;
    }
    memcpy(ciphertext, nonce, sizeof(nonce));
    *ciphertext_len = ct_len + sizeof(nonce);
    return 0;
}

int decrypt_message(const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *key,
                    unsigned char *plaintext, size_t *plaintext_len)
{
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
            nonce, key) != 0)
    {
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
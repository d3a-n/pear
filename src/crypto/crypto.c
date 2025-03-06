#include "../../include/crypto.h"
#include "../../include/common.h"
#include <string.h>
#include <time.h>

/* Triple Diffie-Hellman key exchange */
int perform_3dh_key_exchange(int sock,
                            const char *local_username,
                            char *remote_username,
                            session_keys_t *session_keys,
                            int is_server)
{
    if (!local_username || !remote_username || !session_keys) {
        return -1;
    }

    // Define total message size for key exchange
    #define KEY_EXCHANGE_MSG_SIZE (1 + USERNAME_SIZE + (crypto_box_PUBLICKEYBYTES * 3))

    // Generate three ephemeral key pairs
    key_pair_t identity_key;
    key_pair_t ephemeral_key1;
    key_pair_t ephemeral_key2;

    // Generate identity key pair
    if (crypto_box_keypair(identity_key.public_key, identity_key.secret_key) != 0) {
        return -1;
    }

    // Generate first ephemeral key pair
    if (crypto_box_keypair(ephemeral_key1.public_key, ephemeral_key1.secret_key) != 0) {
        secure_memzero(&identity_key, sizeof(identity_key));
        return -1;
    }

    // Generate second ephemeral key pair
    if (crypto_box_keypair(ephemeral_key2.public_key, ephemeral_key2.secret_key) != 0) {
        secure_memzero(&identity_key, sizeof(identity_key));
        secure_memzero(&ephemeral_key1, sizeof(ephemeral_key1));
        return -1;
    }

    // Build the outgoing key exchange message
    unsigned char send_buffer[KEY_EXCHANGE_MSG_SIZE];
    size_t username_len = strlen(local_username);
    if (username_len > USERNAME_SIZE) {
        username_len = USERNAME_SIZE; // ensure it does not exceed maximum
    }

    // Store the username length as the first byte
    send_buffer[0] = (uint8_t)username_len;

    // Copy the username into a fixed-size field (pad with zeros if needed)
    memset(send_buffer + 1, 0, USERNAME_SIZE);
    memcpy(send_buffer + 1, local_username, username_len);

    // Append the three public keys
    memcpy(send_buffer + 1 + USERNAME_SIZE, 
           identity_key.public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(send_buffer + 1 + USERNAME_SIZE + crypto_box_PUBLICKEYBYTES,
           ephemeral_key1.public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(send_buffer + 1 + USERNAME_SIZE + (2 * crypto_box_PUBLICKEYBYTES),
           ephemeral_key2.public_key, crypto_box_PUBLICKEYBYTES);

    // Send the key exchange message
    if (send_all(sock, send_buffer, KEY_EXCHANGE_MSG_SIZE, 0) < 0) {
        secure_memzero(&identity_key, sizeof(identity_key));
        secure_memzero(&ephemeral_key1, sizeof(ephemeral_key1));
        secure_memzero(&ephemeral_key2, sizeof(ephemeral_key2));
        return -1;
    }

    // Receive the remote key exchange message
    unsigned char recv_buffer[KEY_EXCHANGE_MSG_SIZE];
    ssize_t received = 0;
    size_t total_received = 0;

    while (total_received < KEY_EXCHANGE_MSG_SIZE) {
        received = recv(sock, (char *)(recv_buffer + total_received), 
                        KEY_EXCHANGE_MSG_SIZE - total_received, 0);
        if (received <= 0) {
            if (received < 0 && (errno == EINTR || errno == EAGAIN)) {
                continue;
            }
            secure_memzero(&identity_key, sizeof(identity_key));
            secure_memzero(&ephemeral_key1, sizeof(ephemeral_key1));
            secure_memzero(&ephemeral_key2, sizeof(ephemeral_key2));
            return -1;
        }
        total_received += received;
    }

    // Extract the remote username
    uint8_t remote_username_len = recv_buffer[0];
    if (remote_username_len > USERNAME_SIZE) {
        remote_username_len = USERNAME_SIZE;
    }
    memcpy(remote_username, recv_buffer + 1, remote_username_len);
    remote_username[remote_username_len] = '\0'; // Ensure null-termination

    // Extract the remote public keys
    unsigned char remote_identity_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char remote_ephemeral_pk1[crypto_box_PUBLICKEYBYTES];
    unsigned char remote_ephemeral_pk2[crypto_box_PUBLICKEYBYTES];

    memcpy(remote_identity_pk, 
           recv_buffer + 1 + USERNAME_SIZE, 
           crypto_box_PUBLICKEYBYTES);
    memcpy(remote_ephemeral_pk1, 
           recv_buffer + 1 + USERNAME_SIZE + crypto_box_PUBLICKEYBYTES, 
           crypto_box_PUBLICKEYBYTES);
    memcpy(remote_ephemeral_pk2, 
           recv_buffer + 1 + USERNAME_SIZE + (2 * crypto_box_PUBLICKEYBYTES), 
           crypto_box_PUBLICKEYBYTES);

    // Perform Triple Diffie-Hellman (3DH) key agreement
    unsigned char dh1[crypto_scalarmult_BYTES]; // identity_key * remote_ephemeral_pk1
    unsigned char dh2[crypto_scalarmult_BYTES]; // ephemeral_key1 * remote_identity_pk
    unsigned char dh3[crypto_scalarmult_BYTES]; // ephemeral_key1 * remote_ephemeral_pk1

    if (crypto_scalarmult(dh1, identity_key.secret_key, remote_ephemeral_pk1) != 0 ||
        crypto_scalarmult(dh2, ephemeral_key1.secret_key, remote_identity_pk) != 0 ||
        crypto_scalarmult(dh3, ephemeral_key1.secret_key, remote_ephemeral_pk1) != 0) {
        secure_memzero(&identity_key, sizeof(identity_key));
        secure_memzero(&ephemeral_key1, sizeof(ephemeral_key1));
        secure_memzero(&ephemeral_key2, sizeof(ephemeral_key2));
        secure_memzero(dh1, sizeof(dh1));
        secure_memzero(dh2, sizeof(dh2));
        secure_memzero(dh3, sizeof(dh3));
        return -1;
    }

    // Combine the DH outputs into a master secret
    unsigned char master_secret[crypto_scalarmult_BYTES * 3];
    memcpy(master_secret, dh1, crypto_scalarmult_BYTES);
    memcpy(master_secret + crypto_scalarmult_BYTES, dh2, crypto_scalarmult_BYTES);
    memcpy(master_secret + (2 * crypto_scalarmult_BYTES), dh3, crypto_scalarmult_BYTES);

    // Derive session keys using HKDF
    unsigned char salt[crypto_generichash_BYTES];
    randombytes_buf(salt, sizeof(salt));

    if (is_server) {
        // Server: rx_key = HKDF(master_secret, "c2s"), tx_key = HKDF(master_secret, "s2c")
        derive_keys(master_secret, sizeof(master_secret), salt, sizeof(salt), 
                   (const unsigned char *)"c2s", 3, &session_keys->rx_key);
        derive_keys(master_secret, sizeof(master_secret), salt, sizeof(salt), 
                   (const unsigned char *)"s2c", 3, &session_keys->tx_key);
    } else {
        // Client: tx_key = HKDF(master_secret, "c2s"), rx_key = HKDF(master_secret, "s2c")
        derive_keys(master_secret, sizeof(master_secret), salt, sizeof(salt), 
                   (const unsigned char *)"c2s", 3, &session_keys->tx_key);
        derive_keys(master_secret, sizeof(master_secret), salt, sizeof(salt), 
                   (const unsigned char *)"s2c", 3, &session_keys->rx_key);
    }

    // Initialize the ratchet with the second ephemeral key pair
    if (initialize_ratchet(&session_keys->ratchet, 
                          &session_keys->rx_key, 
                          &ephemeral_key2, 
                          remote_ephemeral_pk2, 
                          is_server) != 0) {
        secure_memzero(&identity_key, sizeof(identity_key));
        secure_memzero(&ephemeral_key1, sizeof(ephemeral_key1));
        secure_memzero(&ephemeral_key2, sizeof(ephemeral_key2));
        secure_memzero(master_secret, sizeof(master_secret));
        secure_memzero(dh1, sizeof(dh1));
        secure_memzero(dh2, sizeof(dh2));
        secure_memzero(dh3, sizeof(dh3));
        secure_memzero(session_keys, sizeof(session_keys_t));
        return -1;
    }

    // Clean up sensitive data
    secure_memzero(&identity_key, sizeof(identity_key));
    secure_memzero(&ephemeral_key1, sizeof(ephemeral_key1));
    secure_memzero(&ephemeral_key2, sizeof(ephemeral_key2));
    secure_memzero(master_secret, sizeof(master_secret));
    secure_memzero(dh1, sizeof(dh1));
    secure_memzero(dh2, sizeof(dh2));
    secure_memzero(dh3, sizeof(dh3));

    return 0;
}

/* Initialize the Double Ratchet */
int initialize_ratchet(ratchet_state_t *ratchet, 
                      const symmetric_key_t *shared_secret,
                      const key_pair_t *dh_pair,
                      const unsigned char *remote_public_key,
                      int is_sender)
{
    if (!ratchet || !shared_secret || !dh_pair || !remote_public_key) {
        return -1;
    }

    // Copy the DH key pair
    memcpy(&ratchet->dh_pair, dh_pair, sizeof(key_pair_t));

    // Copy the remote public key
    memcpy(ratchet->remote_dh_pair.public_key, remote_public_key, crypto_box_PUBLICKEYBYTES);
    secure_memzero(ratchet->remote_dh_pair.secret_key, crypto_box_SECRETKEYBYTES);

    // Initialize the root key with the shared secret
    memcpy(&ratchet->root_key, shared_secret, sizeof(symmetric_key_t));

    // Initialize the chain keys
    if (is_sender) {
        // Derive the sending chain key
        derive_keys(shared_secret->key, KEY_SIZE, NULL, 0, 
                   (const unsigned char *)"sending_chain", 13, &ratchet->chain_key_send);
        // Initialize the receiving chain key (will be derived on first message)
        secure_memzero(&ratchet->chain_key_recv, sizeof(symmetric_key_t));
    } else {
        // Derive the receiving chain key
        derive_keys(shared_secret->key, KEY_SIZE, NULL, 0, 
                   (const unsigned char *)"receiving_chain", 15, &ratchet->chain_key_recv);
        // Initialize the sending chain key (will be derived on first message)
        secure_memzero(&ratchet->chain_key_send, sizeof(symmetric_key_t));
    }

    // Initialize counters
    ratchet->send_count = 0;
    ratchet->recv_count = 0;
    ratchet->initialized = 1;

    return 0;
}

/* Ratchet encryption */
int ratchet_encrypt(ratchet_state_t *ratchet,
                   const unsigned char *plaintext, size_t plaintext_len,
                   unsigned char *ciphertext, size_t *ciphertext_len)
{
    if (!ratchet || !plaintext || !ciphertext || !ciphertext_len || !ratchet->initialized) {
        return -1;
    }

    // Derive a message key from the sending chain key
    symmetric_key_t message_key;
    derive_keys(ratchet->chain_key_send.key, KEY_SIZE, NULL, 0, 
               (const unsigned char *)"message_key", 11, &message_key);

    // Update the sending chain key
    symmetric_key_t new_chain_key;
    derive_keys(ratchet->chain_key_send.key, KEY_SIZE, NULL, 0, 
               (const unsigned char *)"next_chain", 10, &new_chain_key);
    memcpy(&ratchet->chain_key_send, &new_chain_key, sizeof(symmetric_key_t));
    secure_memzero(&new_chain_key, sizeof(symmetric_key_t));

    // Encrypt the message
    int result = encrypt_message(plaintext, plaintext_len, &message_key, 
                                ciphertext, ciphertext_len);

    // Clean up
    secure_memzero(&message_key, sizeof(symmetric_key_t));
    ratchet->send_count++;

    return result;
}

/* Ratchet decryption */
int ratchet_decrypt(ratchet_state_t *ratchet,
                   const unsigned char *ciphertext, size_t ciphertext_len,
                   unsigned char *plaintext, size_t *plaintext_len)
{
    if (!ratchet || !ciphertext || !plaintext || !plaintext_len || !ratchet->initialized) {
        return -1;
    }

    // Derive a message key from the receiving chain key
    symmetric_key_t message_key;
    derive_keys(ratchet->chain_key_recv.key, KEY_SIZE, NULL, 0, 
               (const unsigned char *)"message_key", 11, &message_key);

    // Update the receiving chain key
    symmetric_key_t new_chain_key;
    derive_keys(ratchet->chain_key_recv.key, KEY_SIZE, NULL, 0, 
               (const unsigned char *)"next_chain", 10, &new_chain_key);
    memcpy(&ratchet->chain_key_recv, &new_chain_key, sizeof(symmetric_key_t));
    secure_memzero(&new_chain_key, sizeof(symmetric_key_t));

    // Decrypt the message
    int result = decrypt_message(ciphertext, ciphertext_len, &message_key, 
                                plaintext, plaintext_len);

    // Clean up
    secure_memzero(&message_key, sizeof(symmetric_key_t));
    ratchet->recv_count++;

    return result;
}

/* Message encryption */
int encrypt_message(const unsigned char *plaintext, size_t plaintext_len,
                   const symmetric_key_t *key,
                   unsigned char *ciphertext, size_t *ciphertext_len)
{
    if (!plaintext || !key || !ciphertext || !ciphertext_len) {
        return -1;
    }

    // Generate a random nonce
    unsigned char nonce[NONCE_SIZE];
    randombytes_buf(nonce, NONCE_SIZE);

    // Copy the nonce to the beginning of the ciphertext
    memcpy(ciphertext, nonce, NONCE_SIZE);

    // Encrypt the message
    unsigned long long ct_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext + NONCE_SIZE, &ct_len,
            plaintext, plaintext_len,
            NULL, 0,
            NULL,
            nonce, key->key) != 0)
    {
        return -1;
    }

    *ciphertext_len = ct_len + NONCE_SIZE;
    return 0;
}

/* Message decryption */
int decrypt_message(const unsigned char *ciphertext, size_t ciphertext_len,
                   const symmetric_key_t *key,
                   unsigned char *plaintext, size_t *plaintext_len)
{
    if (!ciphertext || !key || !plaintext || !plaintext_len) {
        return -1;
    }

    if (ciphertext_len < NONCE_SIZE + TAG_SIZE) {
        return -1;
    }

    // Extract the nonce from the beginning of the ciphertext
    unsigned char nonce[NONCE_SIZE];
    memcpy(nonce, ciphertext, NONCE_SIZE);

    // Decrypt the message
    unsigned long long pt_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &pt_len,
            NULL,
            ciphertext + NONCE_SIZE, ciphertext_len - NONCE_SIZE,
            NULL, 0,
            nonce, key->key) != 0)
    {
        return -1;
    }

    *plaintext_len = pt_len;
    return 0;
}

/* Key derivation using HKDF */
int derive_keys(const unsigned char *input, size_t input_len,
               const unsigned char *salt, size_t salt_len,
               const unsigned char *info, size_t info_len,
               symmetric_key_t *output_key)
{
    if (!input || !output_key) {
        return -1;
    }

    // If salt is NULL or salt_len is 0, use a zero key
    unsigned char zero_salt[crypto_generichash_KEYBYTES] = {0};
    const unsigned char *actual_salt = salt ? salt : zero_salt;
    const size_t actual_salt_len = salt ? salt_len : sizeof(zero_salt);

    // Extract phase: HMAC-BLAKE2b(salt, input)
    unsigned char prk[crypto_generichash_BYTES];
    crypto_generichash_state state;

    // Initialize the hash state with the salt as the key
    if (crypto_generichash_init(&state, actual_salt, actual_salt_len, sizeof(prk)) != 0) {
        return -1;
    }

    // Update with the input
    if (crypto_generichash_update(&state, input, input_len) != 0) {
        return -1;
    }

    // Finalize the hash
    if (crypto_generichash_final(&state, prk, sizeof(prk)) != 0) {
        return -1;
    }

    // Expand phase: HMAC-BLAKE2b(prk, info | 0x01)
    unsigned char counter = 0x01;
    
    // Initialize the hash state with the PRK as the key
    if (crypto_generichash_init(&state, prk, sizeof(prk), KEY_SIZE) != 0) {
        secure_memzero(prk, sizeof(prk));
        return -1;
    }

    // Update with the info if provided
    if (info && info_len > 0) {
        if (crypto_generichash_update(&state, info, info_len) != 0) {
            secure_memzero(prk, sizeof(prk));
            return -1;
        }
    }

    // Update with the counter
    if (crypto_generichash_update(&state, &counter, 1) != 0) {
        secure_memzero(prk, sizeof(prk));
        return -1;
    }

    // Finalize the hash
    if (crypto_generichash_final(&state, output_key->key, KEY_SIZE) != 0) {
        secure_memzero(prk, sizeof(prk));
        return -1;
    }

    // Clean up
    secure_memzero(prk, sizeof(prk));
    return 0;
}

/* Add random padding to a message - No-op version (feature removed) */
size_t add_random_padding(unsigned char *buffer, size_t content_len, size_t max_len)
{
    // Feature removed - return content length with no padding
    return content_len;
}

/* Remove padding from a message - No-op version (feature removed) */
size_t remove_padding(unsigned char *buffer, size_t buffer_len)
{
    // Feature removed - return buffer length unchanged
    return buffer_len;
}

/* Securely wipe sensitive data */
void wipe_sensitive_data(void *data, size_t len)
{
    if (data && len > 0) {
        sodium_memzero(data, len);
    }
}

/* Wipe session keys */
void wipe_session_keys(session_keys_t *keys)
{
    if (keys) {
        wipe_sensitive_data(&keys->tx_key, sizeof(symmetric_key_t));
        wipe_sensitive_data(&keys->rx_key, sizeof(symmetric_key_t));
        wipe_sensitive_data(&keys->ratchet, sizeof(ratchet_state_t));
    }
}

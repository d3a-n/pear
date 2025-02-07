#include "chat.h"
#include "crypto_utils.h"
#include "commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void chat_session(chat_info *info)
{
    LOG_STEP("Starting chat session...");

    pthread_t send_thread, recv_thread;

    if (pthread_create(&recv_thread, NULL, receive_messages, (void *)info) != 0) {
        LOG_ERROR("Failed to create receive thread.");
        return;
    }
    LOG_INFO("Receive thread created successfully.");

    if (pthread_create(&send_thread, NULL, send_messages, (void *)info) != 0) {
        LOG_ERROR("Failed to create send thread.");
        pthread_cancel(recv_thread);
        return;
    }
    LOG_INFO("Send thread created successfully.");

    /* Wait for sending thread to exit. */
    pthread_join(send_thread, NULL);
    LOG_STEP("Send thread terminated.");

    /* Wait for receiving thread to exit. */
    pthread_join(recv_thread, NULL);
    LOG_STEP("Receive thread terminated.");

    /* Close socket after both threads have finished. */
    socket_close(info->sock);
    LOG_INFO("Chat session ended.");
}

void *receive_messages(void *arg)
{
    chat_info *info = (chat_info *)arg;
    unsigned char buffer[BUFFER_SIZE + 
                         crypto_aead_chacha20poly1305_IETF_ABYTES +
                         crypto_aead_chacha20poly1305_IETF_NPUBBYTES];

    /* Continuously receive encrypted data and decrypt. */
    while (1) {
        ssize_t bytes_received = recv(info->sock, (char *)buffer, sizeof(buffer), 0);
        if (bytes_received > 0) {
            unsigned char plaintext[BUFFER_SIZE + 1];
            size_t plaintext_len = 0;

            if (decrypt_message(buffer, bytes_received, info->rx_key,
                                plaintext, &plaintext_len) == 0)
            {
                plaintext[plaintext_len] = '\0';
                /* Print remote user's message, then re‐print local prompt. */
                printf("\n<%s> %s\n", info->remote_username, plaintext);
                printf("<%s> ", info->local_username);
                fflush(stdout);
            } else {
                LOG_ERROR("Failed to decrypt incoming message.");
            }
        } else if (bytes_received == 0) {
            LOG_INFO("Connection closed by peer.");
            break;
        } else {
            LOG_ERROR("Receive error or connection dropped.");
            break;
        }
    }
    pthread_exit(NULL);
    return NULL;
}

void *send_messages(void *arg)
{
    chat_info *info = (chat_info *)arg;
    char input_buf[BUFFER_SIZE];

    while (1) {
        /* Prompt for user input. */
        printf("<%s> ", info->local_username);
        fflush(stdout);

        if (!safe_fgets(input_buf, sizeof(input_buf), stdin)) {
            LOG_ERROR("Failed to read input from stdin.");
            break;
        }
        /* Strip newline. */
        input_buf[strcspn(input_buf, "\n")] = '\0';

        /* Ignore empty lines. */
        if (strlen(input_buf) == 0) {
            continue;
        }

        /* Check for slash commands. */
        if (input_buf[0] == '/') {
            /* If process_command returns 0, we exit. */
            if (process_command(info, input_buf) == 0) {
                break;
            }
            continue;
        }

        /* Encrypt the message before sending. */
        unsigned char ciphertext[BUFFER_SIZE + 
                                 crypto_aead_chacha20poly1305_IETF_ABYTES +
                                 crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
        size_t ciphertext_len = 0;

        if (encrypt_message((unsigned char *)input_buf, strlen(input_buf),
                            info->tx_key, ciphertext, &ciphertext_len) != 0)
        {
            LOG_ERROR("Encryption failed. Message not sent.");
            continue;
        }

        /* Send the ciphertext, ensuring it is fully transmitted. */
        ssize_t sent = send_all(info->sock, ciphertext, ciphertext_len, 0);
        if (sent < 0 || (size_t)sent != ciphertext_len) {
            LOG_ERROR("Failed to send complete message.");
            break;
        }
    }
    pthread_exit(NULL);
    return NULL;
}
#include "chat.h"
#include "crypto_utils.h"
#include "commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

static const char *PING_MARKER = "\x01PING\x01";
static const char *PONG_MARKER = "\x01PONG\x01";

void chat_session(chat_info *info) {
    LOG_STEP("Starting chat session...");

    /*
     * If the ephemeral key exchange did not set info->remote_username
     * to something non-empty, set it to "Unknown".
     */
    if (strlen(info->remote_username) == 0) {
        strcpy(info->remote_username, "Unknown");
    }

    pthread_t send_thread, recv_thread;

    if (pthread_create(&recv_thread, NULL, receive_messages, (void *)info) != 0) {
        LOG_ERROR("Failed to create receive thread.");
        return;
    }
    LOG_INFO("Receive thread created.");

    if (pthread_create(&send_thread, NULL, send_messages, (void *)info) != 0) {
        LOG_ERROR("Failed to create send thread.");
        pthread_cancel(recv_thread);
        return;
    }
    LOG_INFO("Send thread created.");

    pthread_join(send_thread, NULL);
    LOG_STEP("Send thread terminated.");

    pthread_join(recv_thread, NULL);
    LOG_STEP("Receive thread terminated.");

    socket_close(info->sock);
    LOG_INFO("Chat session ended.");
}

void *receive_messages(void *arg) {
    chat_info *info = (chat_info *)arg;
    unsigned char buffer[BUFFER_SIZE + 128];

    while (1) {
        // For UDP, one call to recv() gets the entire datagram.
        ssize_t received = recv(info->sock, (char *)buffer, sizeof(buffer), 0);
        if (received <= 0) {
            if (received == 0) {
                LOG_INFO("Connection closed by peer.");
            } else {
                LOG_ERROR("Receive error or connection dropped.");
            }
            break;
        }

        // Decrypt the received datagram
        unsigned char plaintext[BUFFER_SIZE + 1];
        size_t plaintext_len = 0;
        if (decrypt_message(buffer, received, info->rx_key, plaintext, &plaintext_len) != 0) {
            LOG_ERROR("Decryption failed. Disconnecting.");
            break;
        }
        plaintext[plaintext_len] = '\0';

        // Check for ping/pong
        if (strcmp((char *)plaintext, PING_MARKER) == 0) {
            LOG_INFO("Received ping. Sending pong...");
            unsigned char pong_buf[BUFFER_SIZE + 64];
            size_t pong_buf_len = 0;
            if (encrypt_message((unsigned char *)PONG_MARKER, strlen(PONG_MARKER),
                                info->tx_key, pong_buf, &pong_buf_len) == 0) {
                send_all(info->sock, pong_buf, pong_buf_len, 0);
            }
            continue;
        } else if (strcmp((char *)plaintext, PONG_MARKER) == 0) {
            LOG_INFO("Received pong from remote side.");
            continue;
        }

        // Print the received message
        printf("\n<%s> %s\n", info->remote_username, plaintext);
        printf("<%s> ", info->local_username);
        fflush(stdout);
    }

    socket_close(info->sock);
    pthread_exit(NULL);
    return NULL;
}

void *send_messages(void *arg) {
    chat_info *info = (chat_info *)arg;
    char input_buf[BUFFER_SIZE];

    while (1) {
        printf("<%s> ", info->local_username);
        fflush(stdout);

        if (!safe_fgets(input_buf, sizeof(input_buf), stdin)) {
            LOG_ERROR("Failed to read from stdin.");
            break;
        }
        input_buf[strcspn(input_buf, "\n")] = '\0';

        if (strlen(input_buf) == 0)
            continue;

        // Process slash commands
        if (input_buf[0] == '/') {
            int status = process_command(info, input_buf);
            if (status == 0) {
                break;
            }
            continue;
        }

        // Encrypt the plaintext -> ciphertext
        unsigned char ciphertext[BUFFER_SIZE + 128];
        size_t ciphertext_len = 0;
        if (encrypt_message((unsigned char *)input_buf, strlen(input_buf),
                            info->tx_key, ciphertext, &ciphertext_len) != 0) {
            LOG_ERROR("Encryption failed; message not sent.");
            continue;
        }

        // Send one complete datagram
        ssize_t sent = send_all(info->sock, ciphertext, ciphertext_len, 0);
        if (sent < 0 || (size_t)sent != ciphertext_len) {
            LOG_ERROR("Failed to send complete message.");
            break;
        }
    }
    pthread_exit(NULL);
    return NULL;
}
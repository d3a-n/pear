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
    uint32_t net_len;

    while (1) {
        // Read the 4-byte length prefix with MSG_WAITALL
        ssize_t len_received = recv(info->sock, (char *)&net_len, sizeof(net_len), MSG_WAITALL);
        if (len_received <= 0) {
            if (len_received == 0) {
                LOG_INFO("Connection closed by peer.");
            } else {
                LOG_ERROR("Receive error or connection dropped.");
            }
            break;
        }
        if ((size_t)len_received != sizeof(net_len)) {
            LOG_ERROR("Failed to read complete length prefix.");
            break;
        }

        uint32_t msg_len = ntohl(net_len);
        if (msg_len > (BUFFER_SIZE + 128)) {
            LOG_ERROR("Message length %u exceeds maximum allowed.", msg_len);
            break;
        }

        // Allocate space for the ciphertext
        unsigned char *ciphertext = malloc(msg_len);
        if (!ciphertext) {
            LOG_ERROR("Memory allocation failed.");
            break;
        }

        // Read the full ciphertext
        ssize_t bytes_read = recv(info->sock, (char *)ciphertext, msg_len, MSG_WAITALL);
        if (bytes_read != (ssize_t)msg_len) {
            LOG_ERROR("Incomplete ciphertext. Expected %u bytes, got %zd.", msg_len, bytes_read);
            free(ciphertext);
            break;
        }

        // Decrypt
        unsigned char plaintext[BUFFER_SIZE + 1];
        size_t plaintext_len = 0;
        if (decrypt_message(ciphertext, msg_len, info->rx_key, plaintext, &plaintext_len) != 0) {
            free(ciphertext);
            // Ensure error appears on a new line
            printf("\n");
            LOG_ERROR("Decryption failed. Disconnecting client.");
            break;
        }
        free(ciphertext);

        // Null-terminate
        plaintext[plaintext_len] = '\0';

        // Check for ping/pong
        if (strcmp((char *)plaintext, PING_MARKER) == 0) {
            LOG_INFO("Received ping. Sending pong...");
            unsigned char cbuf[BUFFER_SIZE + 64];
            size_t cbuf_len = 0;
            if (encrypt_message((const unsigned char *)PONG_MARKER, strlen(PONG_MARKER),
                                info->tx_key, cbuf, &cbuf_len) == 0)
            {
                send_all(info->sock, cbuf, cbuf_len, 0);
            }
            continue;
        } else if (strcmp((char *)plaintext, PONG_MARKER) == 0) {
            LOG_INFO("Received pong from remote side.");
            continue;
        }

        // Print message on a new line, followed by a new prompt
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
        // Print prompt on its own line
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

        // Normal message => encrypt + send
        unsigned char ciphertext[BUFFER_SIZE + 128];
        size_t ciphertext_len = 0;
        if (encrypt_message((unsigned char *)input_buf, strlen(input_buf),
                            info->tx_key, ciphertext, &ciphertext_len) != 0) {
            LOG_ERROR("Encryption failed; message not sent.");
            continue;
        }

        // Send length prefix
        uint32_t net_msg_len = htonl((uint32_t)ciphertext_len);
        if (send_all(info->sock, &net_msg_len, sizeof(net_msg_len), 0) != (ssize_t)sizeof(net_msg_len)) {
            LOG_ERROR("Failed to send message length.");
            break;
        }

        // Send ciphertext
        ssize_t sent = send_all(info->sock, ciphertext, ciphertext_len, 0);
        if (sent < 0 || (size_t)sent != ciphertext_len) {
            LOG_ERROR("Failed to send complete message.");
            break;
        }
    }
    pthread_exit(NULL);
    return NULL;
}
#include "chat.h"
#include "common.h"
#include "crypto_utils.h"
#include "commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void chat_session(ChatInfo *info) {
    printf("[STEP] Starting chat session...\n");
    
    pthread_t send_thread, recv_thread;
    
    if (pthread_create(&recv_thread, NULL, receive_messages, (void*)info) != 0) {
        fprintf(stderr, "[ERROR] Failed to create receive thread.\n");
        return;
    }
    printf("[INFO] Receive thread created successfully.\n");
    
    if (pthread_create(&send_thread, NULL, send_messages, (void*)info) != 0) {
        fprintf(stderr, "[ERROR] Failed to create send thread.\n");
        pthread_cancel(recv_thread);
        return;
    }
    printf("[INFO] Send thread created successfully.\n");
    
    pthread_join(send_thread, NULL);
    printf("[STEP] Send thread terminated.\n");
    
    pthread_join(recv_thread, NULL);
    printf("[STEP] Receive thread terminated.\n");
    
    socket_close(info->sock);
    printf("[INFO] Chat session ended.\n");
}

void *receive_messages(void *arg) {
    ChatInfo *info = (ChatInfo*)arg;
    unsigned char buffer[BUFFER_SIZE + crypto_aead_chacha20poly1305_IETF_ABYTES +
                           crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    // In the receive loop we only show errors (if any).
    while (1) {
        ssize_t bytes_received = recv(info->sock, (char*)buffer, sizeof(buffer), 0);
        if (bytes_received > 0) {
            unsigned char plaintext[BUFFER_SIZE];
            size_t plaintext_len = 0;
            if (decrypt_message(buffer, bytes_received, info->rx_key, plaintext, &plaintext_len) == 0) {
                plaintext[plaintext_len] = '\0';
                // Display only the decrypted chat message.
                printf("\n<%s> %s\n", info->remote_username, plaintext);
                printf("<%s> ", info->local_username);
                fflush(stdout);
            } else {
                fprintf(stderr, "Error: Failed to decrypt message.\n");
            }
        } else if (bytes_received == 0) {
            printf("\nConnection closed by peer.\n");
            break;
        } else {
            fprintf(stderr, "Error: Receive error or connection dropped.\n");
            break;
        }
    }
    pthread_exit(NULL);
    return NULL;
}

void *send_messages(void *arg) {
    ChatInfo *info = (ChatInfo*)arg;
    char input_buf[BUFFER_SIZE];
    // In the send loop we show only error messages (if any occur).
    while (1) {
        printf("<%s> ", info->local_username);
        fflush(stdout);
        
        if (!fgets(input_buf, sizeof(input_buf), stdin)) {
            fprintf(stderr, "Error: Failed to read input from stdin.\n");
            break;
        }
        input_buf[strcspn(input_buf, "\n")] = '\0';
        if (strlen(input_buf) == 0)
            continue;
        
        // If input is a command, process it.
        if (input_buf[0] == '/') {
            process_command(info, input_buf);
            if (strcasecmp(input_buf, "/exit") == 0)
                break;
            continue;
        }
        
        unsigned char ciphertext[BUFFER_SIZE +
                                 crypto_aead_chacha20poly1305_IETF_ABYTES +
                                 crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
        size_t ciphertext_len = 0;
        if (encrypt_message((unsigned char*)input_buf, strlen(input_buf),
                            info->tx_key, ciphertext, &ciphertext_len) != 0) {
            fprintf(stderr, "Error: Encryption failed. Message not sent.\n");
            continue;
        }
        ssize_t sent = send(info->sock, (char*)ciphertext, ciphertext_len, 0);
        if (sent != (ssize_t)ciphertext_len) {
            fprintf(stderr, "Error: Failed to send complete message.\n");
            break;
        }
    }
    pthread_exit(NULL);
    return NULL;
}

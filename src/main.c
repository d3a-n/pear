#include "common.h"
#include "crypto_utils.h"
#include "chat.h"
#include "commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef _WIN32
#include <winsock2.h>
#endif

// Global variables for potential server administration (unused in this simple version)
Client* client_list = NULL;
pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;
Ban* ban_list = NULL;
pthread_mutex_t ban_list_mutex = PTHREAD_MUTEX_INITIALIZER;

// Helper function to safely read a line from input and flush extra characters if needed.
static int safe_fgets(char *buffer, size_t size, FILE *stream) {
    if (fgets(buffer, size, stream) == NULL)
        return 0;
    if (strchr(buffer, '\n') == NULL) {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF)
            ;
    }
    return 1;
}

// Sets a 5-second timeout for both sending and receiving on a socket.
void set_socket_timeouts(int sock) {
    struct timeval timeout;
    timeout.tv_sec = 5;       // 5 seconds timeout
    timeout.tv_usec = 0;
#ifdef _WIN32
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) < 0) {
        fprintf(stderr, "[ERROR] Failed to set receive timeout.\n");
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout)) < 0) {
        fprintf(stderr, "[ERROR] Failed to set send timeout.\n");
    }
#else
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("[ERROR] Failed to set receive timeout");
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("[ERROR] Failed to set send timeout");
    }
#endif
    printf("[INFO] Socket timeouts set to 5 seconds.\n");
}

void init_sockets_and_crypto() {
    printf("[STEP] Initializing sockets and libsodium...\n");
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        fprintf(stderr, "[ERROR] WSAStartup failed.\n");
        exit(EXIT_FAILURE);
    }
    printf("[INFO] Windows Sockets initialized successfully.\n");
#endif
    if (sodium_init() < 0) {
        fprintf(stderr, "[ERROR] libsodium initialization failed.\n");
        exit(EXIT_FAILURE);
    }
    printf("[INFO] libsodium initialized successfully.\n");
}

void cleanup_sockets() {
    printf("[STEP] Cleaning up sockets...\n");
#ifdef _WIN32
    WSACleanup();
#endif
    printf("[INFO] Sockets cleaned up.\n");
}

int get_username(char *username, size_t size) {
    while (1) {
        printf("[STEP] Prompting for username...\n");
        printf("Enter your username (alphanumeric and underscores only): ");
        if (!safe_fgets(username, size, stdin)) {
            fprintf(stderr, "[ERROR] Failed to read username.\n");
            return -1;
        }
        username[strcspn(username, "\n")] = '\0';
        if (strlen(username) == 0) {
            printf("[WARNING] Username cannot be empty.\n");
            continue;
        }
        int valid = 1;
        for (size_t i = 0; i < strlen(username); i++) {
            if (!isalnum((unsigned char)username[i]) && username[i] != '_') {
                valid = 0;
                break;
            }
        }
        if (!valid) {
            printf("[WARNING] Invalid username. Only letters, digits, and underscores are allowed.\n");
            continue;
        }
        printf("[INFO] Username accepted: %s\n", username);
        break;
    }
    return 0;
}

int is_valid_ip(const char *ip) {
    int period_count = 0;
    size_t len = strlen(ip);
    if (len < 7 || len > 15)
        return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)ip[i]) && ip[i] != '.')
            return 0;
        if (ip[i] == '.')
            period_count++;
    }
    return (period_count == 3);
}

int is_valid_port(const char *port_str) {
    char *endptr;
    long port = strtol(port_str, &endptr, 10);
    if (*endptr != '\0' || port < 1 || port > 65535)
        return 0;
    return 1;
}

// Prompts for a valid IP address once, then repeatedly asks for a valid port.
void get_valid_ip_and_port(char *host_ip, size_t ip_size, int *host_port) {
    char port_str[10];
    // Prompt for IP address.
    while (1) {
        printf("[STEP] Prompting for server IP...\n");
        printf("Enter server IP: ");
        if (!safe_fgets(host_ip, ip_size, stdin)) {
            fprintf(stderr, "[ERROR] Failed to read server IP.\n");
            continue;
        }
        host_ip[strcspn(host_ip, "\n")] = '\0';
        if (!is_valid_ip(host_ip)) {
            printf("[WARNING] Invalid IP format. Please try again.\n");
            continue;
        }
        break;
    }
    // Prompt for port.
    while (1) {
        printf("[STEP] Prompting for server port...\n");
        printf("Enter server port: ");
        if (!safe_fgets(port_str, sizeof(port_str), stdin)) {
            fprintf(stderr, "[ERROR] Failed to read server port.\n");
            continue;
        }
        port_str[strcspn(port_str, "\n")] = '\0';
        if (!is_valid_port(port_str)) {
            printf("[WARNING] Invalid port. Please enter a number between 1 and 65535.\n");
            continue;
        }
        *host_port = atoi(port_str);
        break;
    }
    printf("[INFO] Server IP and port accepted: %s:%d\n", host_ip, *host_port);
}

void server_mode(const char *username) {
    printf("[STEP] Starting server mode...\n");
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        fprintf(stderr, "[ERROR] Could not create server socket.\n");
        exit(EXIT_FAILURE);
    }
    printf("[INFO] Server socket created.\n");
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(0); // Ephemeral port
    
    printf("[STEP] Binding server socket...\n");
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "[ERROR] Binding failed.\n");
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }
    
    socklen_t addr_len = sizeof(server_addr);
    if (getsockname(server_socket, (struct sockaddr*)&server_addr, &addr_len) == -1) {
        fprintf(stderr, "[ERROR] getsockname failed.\n");
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }
    int assigned_port = ntohs(server_addr.sin_port);
    printf("[INFO] Server socket bound to port: %d\n", assigned_port);
    
    // Display the server's IP using hostname resolution.
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct hostent *host_entry = gethostbyname(hostname);
        if (host_entry && host_entry->h_addr_list[0]) {
            char *ip = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
            printf("[INFO] Server running on %s:%d\n", ip, assigned_port);
        }
    }
    
    printf("[STEP] Listening for incoming connections...\n");
    if (listen(server_socket, 5) < 0) {
        fprintf(stderr, "[ERROR] Listen failed.\n");
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }
    
    printf("[STEP] Waiting for a client to connect...\n");
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_sock = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_sock < 0) {
        fprintf(stderr, "[ERROR] Accept failed.\n");
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }
    printf("[INFO] A client has connected.\n");
    
    ChatInfo info;
    memset(&info, 0, sizeof(info));
    info.sock = client_sock;
    strncpy(info.local_username, username, USERNAME_SIZE - 1);
    
    printf("[STEP] Performing key exchange as server...\n");
    if (perform_key_exchange(client_sock, username, info.remote_username, info.rx_key, info.tx_key, 1) != 0) {
        fprintf(stderr, "[ERROR] Key exchange failed on server side.\n");
        socket_close(client_sock);
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }
    printf("[INFO] Key exchange successful.\n");
    
    printf("[STEP] Performing username handshake (server side)...\n");
    ssize_t n = recv(client_sock, info.remote_username, USERNAME_SIZE - 1, 0);
    if (n <= 0) {
        fprintf(stderr, "[ERROR] Failed to receive client's username.\n");
        socket_close(client_sock);
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }
    info.remote_username[n] = '\0';
    printf("[INFO] Received client username: %s\n", info.remote_username);
    
    printf("[STEP] Sending server username to client...\n");
    if (send(client_sock, username, strlen(username), 0) < 0) {
        fprintf(stderr, "[ERROR] Failed to send server username.\n");
        socket_close(client_sock);
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("[INFO] Client '%s' connected from IP: %s\n", info.remote_username, client_ip);
    
    printf("[STEP] Starting chat session with client '%s'...\n", info.remote_username);
    chat_session(&info);
    
    socket_close(server_socket);
    printf("[INFO] Server mode terminated.\n");
}

void client_mode(const char *username) {
    printf("[STEP] Starting client mode...\n");
    char server_ip[256];
    int server_port;
    get_valid_ip_and_port(server_ip, sizeof(server_ip), &server_port);
    
    int client_socket;
    while (1) {
        printf("[STEP] Creating client socket...\n");
        client_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (client_socket < 0) {
            fprintf(stderr, "[ERROR] Could not create client socket.\n");
            exit(EXIT_FAILURE);
        }
    
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port   = htons(server_port);
        if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
            fprintf(stderr, "[ERROR] Invalid server IP address.\n");
            socket_close(client_socket);
            exit(EXIT_FAILURE);
        }
    
        printf("[STEP] Attempting to connect to server %s:%d...\n", server_ip, server_port);
        if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            printf("[INFO] Successfully connected to server.\n");
            break;
        } else {
            socket_close(client_socket);
            char choice[10];
            while (1) {
                printf("[INPUT] Type 'r' to retry or 'n' to re-enter IP/port: ");
                if (!safe_fgets(choice, sizeof(choice), stdin)) {
                    fprintf(stderr, "[ERROR] Failed to read input.\n");
                    continue;
                }
                choice[strcspn(choice, "\n")] = '\0';
                if (strlen(choice) == 1 && tolower((unsigned char)choice[0]) == 'r') {
                    printf("[INFO] Retrying connection...\n");
                    break;
                } else if (strlen(choice) == 1 && tolower((unsigned char)choice[0]) == 'n') {
                    printf("[INFO] Re-entering IP/port...\n");
                    get_valid_ip_and_port(server_ip, sizeof(server_ip), &server_port);
                    break;
                } else {
                    printf("[WARNING] Invalid input. Please try again.\n");
                }
            }
        }
    }
    
    ChatInfo info;
    memset(&info, 0, sizeof(info));
    info.sock = client_socket;
    strncpy(info.local_username, username, USERNAME_SIZE - 1);
    
    printf("[STEP] Performing key exchange as client...\n");
    if (perform_key_exchange(client_socket, username, info.remote_username, info.rx_key, info.tx_key, 0) != 0) {
        fprintf(stderr, "[ERROR] Key exchange failed on client side.\n");
        socket_close(client_socket);
        exit(EXIT_FAILURE);
    }
    printf("[INFO] Key exchange successful.\n");
    
    printf("[STEP] Sending client username to server...\n");
    if (send(client_socket, username, strlen(username), 0) < 0) {
        fprintf(stderr, "[ERROR] Failed to send client username.\n");
        socket_close(client_socket);
        exit(EXIT_FAILURE);
    }
    
    ssize_t n = recv(client_socket, info.remote_username, USERNAME_SIZE - 1, 0);
    if (n <= 0) {
        fprintf(stderr, "[ERROR] Failed to receive server username.\n");
        socket_close(client_socket);
        exit(EXIT_FAILURE);
    }
    info.remote_username[n] = '\0';
    printf("[INFO] Received server username: %s\n", info.remote_username);
    
    printf("[STEP] Starting chat session with server '%s'...\n", info.remote_username);
    chat_session(&info);
    
    printf("[INFO] Client mode terminated.\n");
}

int main() {
    printf("[STEP] Application starting...\n");
    init_sockets_and_crypto();
    
    char username[USERNAME_SIZE];
    if (get_username(username, sizeof(username)) != 0) {
        cleanup_sockets();
        exit(EXIT_FAILURE);
    }
    
    char choice[10];
    while (1) {
        printf("[STEP] Prompting for mode selection...\n");
        printf("Press 'c' to connect as client, or press ENTER to run as server: ");
        if (!safe_fgets(choice, sizeof(choice), stdin)) {
            fprintf(stderr, "[ERROR] Failed to read mode selection.\n");
            continue;
        }
        choice[strcspn(choice, "\n")] = '\0';
        if ((strlen(choice) == 0) || (strlen(choice) == 1 && tolower((unsigned char)choice[0]) == 'c')) {
            break;
        } else {
            printf("[WARNING] Invalid input. Please press 'c' for client or ENTER for server.\n");
        }
    }
    
    if (strlen(choice) == 1 && tolower((unsigned char)choice[0]) == 'c') {
        client_mode(username);
    } else {
        server_mode(username);
    }
    
    cleanup_sockets();
    printf("[STEP] Application terminating.\n");
    return 0;
}

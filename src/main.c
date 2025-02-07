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

static void init_sockets_and_crypto(void);
static void cleanup_sockets(void);
static int get_username(char *username, size_t size);
static void server_mode(const char *username);
static void client_mode(const char *username);

/* ---------------------------------------------------------------------------
 * MAIN
 * --------------------------------------------------------------------------- */
int main(void) {
    LOG_STEP("Application starting...");
    init_sockets_and_crypto();

    char username[USERNAME_SIZE];
    if (get_username(username, sizeof(username)) != 0) {
        cleanup_sockets();
        exit(EXIT_FAILURE);
    }

    char choice[10];
    while (1) {
        LOG_STEP("Prompting for mode selection...");
        printf("Press 'c' to connect as client, or ENTER to run as server: ");
        if (!safe_fgets(choice, sizeof(choice), stdin)) {
            LOG_ERROR("Failed to read mode selection.");
            continue;
        }
        choice[strcspn(choice, "\n")] = '\0';
        if (strlen(choice) == 0 || (strlen(choice) == 1 && tolower((unsigned char)choice[0]) == 'c')) {
            break;
        } else {
            LOG_WARNING("Invalid input. Press 'c' (client) or ENTER (server).");
        }
    }

    if (strlen(choice) == 1 && tolower((unsigned char)choice[0]) == 'c') {
        client_mode(username);
    } else {
        server_mode(username);
    }

    cleanup_sockets();
    LOG_STEP("Application terminating.");
    return 0;
}

/* ---------------------------------------------------------------------------
 * UTILITY FUNCTIONS
 * --------------------------------------------------------------------------- */
static void init_sockets_and_crypto(void) {
    LOG_STEP("Initializing sockets and libsodium...");
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        LOG_ERROR("WSAStartup failed.");
        exit(EXIT_FAILURE);
    }
    LOG_INFO("Windows Sockets initialized successfully.");
#endif
    if (sodium_init() < 0) {
        LOG_ERROR("libsodium initialization failed.");
        exit(EXIT_FAILURE);
    }
    LOG_INFO("libsodium initialized successfully.");
}

static void cleanup_sockets(void) {
    LOG_STEP("Cleaning up sockets...");
#ifdef _WIN32
    WSACleanup();
#endif
    LOG_INFO("Sockets cleaned up.");
}

static int get_username(char *username, size_t size) {
    while (1) {
        LOG_STEP("Prompting for username...");
        printf("Enter your username (alphanumeric or underscores): ");
        if (!safe_fgets(username, size, stdin)) {
            LOG_ERROR("Failed to read username.");
            return -1;
        }
        username[strcspn(username, "\n")] = '\0';

        if (strlen(username) == 0) {
            LOG_WARNING("Username cannot be empty.");
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
            LOG_WARNING("Invalid username. Use letters, digits, or underscores.");
            continue;
        }
        LOG_INFO("Username accepted: %s", username);
        break;
    }
    return 0;
}

static int is_valid_ip(const char *ip) {
    int period_count = 0;
    size_t len = strlen(ip);
    if (len < 7 || len > 15) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)ip[i]) && ip[i] != '.')
            return 0;
        if (ip[i] == '.')
            period_count++;
    }
    return (period_count == 3);
}

static int is_valid_port(const char *port_str) {
    char *endptr;
    long port = strtol(port_str, &endptr, 10);
    if (*endptr != '\0' || port < 1 || port > 65535)
        return 0;
    return 1;
}

static void prompt_for_ip_and_port(char *host_ip, size_t ip_size, int *host_port) {
    char port_str[10];
    while (1) {
        LOG_STEP("Prompting for server IP...");
        printf("Enter server IP: ");
        if (!safe_fgets(host_ip, ip_size, stdin)) {
            LOG_ERROR("Failed to read server IP.");
            continue;
        }
        host_ip[strcspn(host_ip, "\n")] = '\0';
        if (!is_valid_ip(host_ip)) {
            LOG_WARNING("Invalid IP format. Try again.");
            continue;
        }
        break;
    }
    while (1) {
        LOG_STEP("Prompting for server port...");
        printf("Enter server port: ");
        if (!safe_fgets(port_str, sizeof(port_str), stdin)) {
            LOG_ERROR("Failed to read server port.");
            continue;
        }
        port_str[strcspn(port_str, "\n")] = '\0';
        if (!is_valid_port(port_str)) {
            LOG_WARNING("Invalid port number (valid range: 1–65535). Try again.");
            continue;
        }
        *host_port = atoi(port_str);
        break;
    }
    LOG_INFO("Server IP and port accepted: %s:%d", host_ip, *host_port);
}

/* ---------------------------------------------------------------------------
 * SERVER MODE
 * --------------------------------------------------------------------------- */
static void server_mode(const char *username) {
    LOG_STEP("Starting server mode...");

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        LOG_ERROR("Could not create server socket.");
        exit(EXIT_FAILURE);
    }
    LOG_INFO("Server socket created.");

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(0); // ephemeral port

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        LOG_ERROR("Binding failed.");
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }
    socklen_t addr_len = sizeof(server_addr);
    if (getsockname(server_socket, (struct sockaddr*)&server_addr, &addr_len) == -1) {
        LOG_ERROR("getsockname failed.");
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }
    int assigned_port = ntohs(server_addr.sin_port);
    LOG_INFO("Server socket bound to port: %d", assigned_port);

    // Show server IP if possible
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct hostent *host_entry = gethostbyname(hostname);
        if (host_entry && host_entry->h_addr_list[0]) {
            char *ip = inet_ntoa(*(struct in_addr *)host_entry->h_addr_list[0]);
            LOG_INFO("Server IP: %s, Port: %d", ip, assigned_port);
        }
    }

    if (listen(server_socket, 5) < 0) {
        LOG_ERROR("Listen failed.");
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Loop indefinitely so that if a connection is rejected, we keep listening.
    while (1) {
        LOG_STEP("Awaiting client connection...");
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_sock = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_sock < 0) {
            LOG_ERROR("Accept failed.");
            continue; // or break, but continuing might allow the server to keep running
        }
        LOG_INFO("A client has connected.");

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        // Acceptance prompt
        while (1) {
            printf("Client from IP %s wants to connect. Accept (y/n)? ", client_ip);
            fflush(stdout);

            char choice[10];
            if (!safe_fgets(choice, sizeof(choice), stdin)) {
                LOG_ERROR("Failed to read acceptance choice. Please try again.");
                continue;
            }
            choice[strcspn(choice, "\n")] = '\0';
            if (strlen(choice) == 1) {
                char c = (char)tolower((unsigned char)choice[0]);
                if (c == 'y') {
                    LOG_INFO("Client %s accepted. Sending ACCEPT message...", client_ip);
                    const char *acc_msg = "ACCEPT";
                    if (send_all(client_sock, acc_msg, strlen(acc_msg), 0) <= 0) {
                        LOG_ERROR("Failed to send ACCEPT message.");
                        socket_close(client_sock);
                    } else {
                        // proceed with ephemeral key exchange
                        chat_info info;
                        memset(&info, 0, sizeof(info));
                        info.sock = client_sock;
                        strncpy(info.local_username, username, USERNAME_SIZE - 1);

                        LOG_STEP("Performing triple DH key exchange (server side)...");
                        if (perform_key_exchange(client_sock, username, info.remote_username,
                                                 info.rx_key, info.tx_key, 1) != 0)
                        {
                            LOG_ERROR("Key exchange failed on server side.");
                            socket_close(client_sock);
                        } else {
                            LOG_INFO("Key exchange successful (server side).");

                            // Receive client username
                            LOG_STEP("Receiving client username...");
                            ssize_t n = recv(client_sock, info.remote_username,
                                             USERNAME_SIZE - 1, 0);
                            if (n <= 0) {
                                LOG_ERROR("Failed to receive client username.");
                                socket_close(client_sock);
                            } else {
                                info.remote_username[n] = '\0';
                                LOG_INFO("Client username: %s", info.remote_username);

                                // Send server username
                                LOG_STEP("Sending server username...");
                                if (send_all(client_sock, username, strlen(username), 0) < 0) {
                                    LOG_ERROR("Failed to send server username.");
                                    socket_close(client_sock);
                                } else {
                                    LOG_INFO("Client %s connected from IP: %s",
                                             info.remote_username, client_ip);
                                    LOG_STEP("Starting chat session...");
                                    chat_session(&info);
                                }
                            }
                        }
                    }
                    // Done handling this connection => break from acceptance prompt loop
                    break;
                } else if (c == 'n') {
                    LOG_INFO("Rejected client from IP: %s", client_ip);
                    const char *rej_msg = "REJECT";
                    send_all(client_sock, rej_msg, strlen(rej_msg), 0);
                    socket_close(client_sock);
                    // break from acceptance prompt, but remain in the main while(1) => 
                    // continue listening for next client
                    break;
                }
            }
            LOG_WARNING("Invalid input. Please enter 'y' or 'n'.");
        } // end while(1) acceptance prompt
    } // end while(1) for repeated accept

    // We'll never reach here unless we break out from the loop or terminate externally
    socket_close(server_socket);
    LOG_INFO("Server mode terminated (loop ended).");
}

/* ---------------------------------------------------------------------------
 * CLIENT MODE
 * --------------------------------------------------------------------------- */
static void client_mode(const char *username) {
    LOG_STEP("Starting client mode...");
    char server_ip[256];
    int server_port;
    prompt_for_ip_and_port(server_ip, sizeof(server_ip), &server_port);

    while (1) {
        int client_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (client_socket < 0) {
            LOG_ERROR("Could not create client socket.");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port   = htons(server_port);
        if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
            LOG_ERROR("Invalid server IP.");
            socket_close(client_socket);
            exit(EXIT_FAILURE);
        }

        LOG_STEP("Connecting to server...");
        if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            LOG_INFO("Connected to server.");
            // Wait for ACCEPT or REJECT
            char buffer[128];
            ssize_t read_len = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            if (read_len <= 0) {
                LOG_INFO("Connection closed by peer.");
                socket_close(client_socket);
            } else {
                buffer[read_len] = '\0';
                if (strncmp(buffer, "ACCEPT", 6) == 0) {
                    LOG_INFO("Server accepted connection. Proceeding with key exchange...");
                    chat_info info;
                    memset(&info, 0, sizeof(info));
                    info.sock = client_socket;
                    strncpy(info.local_username, username, USERNAME_SIZE - 1);
                    strncpy(info.last_host_ip, server_ip, sizeof(info.last_host_ip)-1);
                    info.last_host_port = server_port;
                    
                    if (perform_key_exchange(client_socket, username, info.remote_username,
                                             info.rx_key, info.tx_key, 0) != 0)
                    {
                        LOG_ERROR("Key exchange failed on client side.");
                        socket_close(client_socket);
                    } else {
                        LOG_INFO("Key exchange successful (client side).");
                        // Send client username
                        LOG_STEP("Sending client username...");
                        if (send_all(client_socket, username, strlen(username), 0) < 0) {
                            LOG_ERROR("Failed to send client username.");
                            socket_close(client_socket);
                        } else {
                            // Receive server username
                            LOG_STEP("Receiving server username...");
                            ssize_t n = recv(client_socket, info.remote_username,
                                             USERNAME_SIZE - 1, 0);
                            if (n <= 0) {
                                LOG_ERROR("Failed to receive server username.");
                                socket_close(client_socket);
                            } else {
                                info.remote_username[n] = '\0';
                                LOG_INFO("Server username: %s", info.remote_username);
                                LOG_STEP("Starting chat session...");
                                chat_session(&info);
                            }
                        }
                    }
                } else {
                    LOG_INFO("Server did not accept our connection (got: %s).", buffer);
                    socket_close(client_socket);
                }
            }
        } else {
            LOG_WARNING("Connection failed. Retrying or re-enter IP/port?");
            socket_close(client_socket);
        }

        // re-prompt after disconnection
        char choice[10];
        while (1) {
            printf("[INPUT] Type 'r' to retry or 'n' to enter a new IP/port: ");
            if (!safe_fgets(choice, sizeof(choice), stdin)) {
                LOG_ERROR("Failed to read input.");
                continue;
            }
            choice[strcspn(choice, "\n")] = '\0';
            if (strlen(choice) == 1) {
                char c = (char)tolower((unsigned char)choice[0]);
                if (c == 'r' || c == 'n')
                    break;
            }
            LOG_WARNING("Invalid input. Please try again.");
        }
        if (tolower((unsigned char)choice[0]) == 'r') {
            continue;
        } else {
            prompt_for_ip_and_port(server_ip, sizeof(server_ip), &server_port);
            continue;
        }
    }
}
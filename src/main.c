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

/* ---------------------------------------------------------------------------
 * HELPER: Initialize sockets (on Windows) and libsodium.
 * --------------------------------------------------------------------------- */
static void init_sockets_and_crypto(void)
{
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

/* ---------------------------------------------------------------------------
 * HELPER: Cleanup sockets on Windows.
 * --------------------------------------------------------------------------- */
static void cleanup_sockets(void)
{
    LOG_STEP("Cleaning up sockets...");
#ifdef _WIN32
    WSACleanup();
#endif
    LOG_INFO("Sockets cleaned up.");
}

/* ---------------------------------------------------------------------------
 * HELPER: Prompt for a valid username (alphanumeric + underscore).
 * --------------------------------------------------------------------------- */
static int get_username(char *username, size_t size)
{
    while (1) {
        LOG_STEP("Prompting for username...");
        printf("Enter your username (alphanumeric and underscores only): ");
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
            LOG_WARNING("Invalid username. Only letters, digits, and underscores are allowed.");
            continue;
        }
        LOG_INFO("Username accepted: %s", username);
        break;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * HELPER: Validate IPv4 string format.
 * --------------------------------------------------------------------------- */
static int is_valid_ip(const char *ip)
{
    int period_count = 0;
    size_t len = strlen(ip);
    if (len < 7 || len > 15)
        return 0;

    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)ip[i]) && ip[i] != '.') {
            return 0;
        }
        if (ip[i] == '.') {
            period_count++;
        }
    }
    return (period_count == 3);
}

/* ---------------------------------------------------------------------------
 * HELPER: Validate TCP port range.
 * --------------------------------------------------------------------------- */
static int is_valid_port(const char *port_str)
{
    char *endptr;
    long port = strtol(port_str, &endptr, 10);
    if (*endptr != '\0' || port < 1 || port > 65535)
        return 0;
    return 1;
}

/* ---------------------------------------------------------------------------
 * HELPER: Prompt user for IP and Port.
 * --------------------------------------------------------------------------- */
static void prompt_for_ip_and_port(char *host_ip, size_t ip_size, int *host_port)
{
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
            LOG_WARNING("Invalid IP format. Please try again.");
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
            LOG_WARNING("Invalid port. Please enter a number between 1 and 65535.");
            continue;
        }
        *host_port = atoi(port_str);
        break;
    }
    LOG_INFO("Server IP and port accepted: %s:%d", host_ip, *host_port);
}

/* ---------------------------------------------------------------------------
 * SERVER MODE: Bind an ephemeral port, accept one client, do key exchange, chat.
 * --------------------------------------------------------------------------- */
static void server_mode(const char *username)
{
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
    server_addr.sin_port        = htons(0); /* Ephemeral port. */

    LOG_STEP("Binding server socket...");
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        LOG_ERROR("Binding failed.");
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }

    socklen_t addr_len = sizeof(server_addr);
    if (getsockname(server_socket, (struct sockaddr *)&server_addr, &addr_len) == -1) {
        LOG_ERROR("getsockname failed.");
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }
    int assigned_port = ntohs(server_addr.sin_port);
    LOG_INFO("Server socket bound to port: %d", assigned_port);

    /* Show IP using hostname resolution (if available). */
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct hostent *host_entry = gethostbyname(hostname);
        if (host_entry && host_entry->h_addr_list[0]) {
            char *ip = inet_ntoa(*(struct in_addr *)host_entry->h_addr_list[0]);
            LOG_INFO("Server running on %s:%d", ip, assigned_port);
        }
    }

    LOG_STEP("Listening for incoming connections...");
    if (listen(server_socket, 1) < 0) {
        LOG_ERROR("Listen failed.");
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }

    LOG_STEP("Waiting for a client to connect...");
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_sock = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_sock < 0) {
        LOG_ERROR("Accept failed.");
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }
    LOG_INFO("A client has connected.");

    chat_info info;
    memset(&info, 0, sizeof(info));
    info.sock = client_sock;
    strncpy(info.local_username, username, USERNAME_SIZE - 1);

    LOG_STEP("Performing key exchange as server...");
    if (perform_key_exchange(client_sock, username, info.remote_username, info.rx_key, info.tx_key, 1) != 0) {
        LOG_ERROR("Key exchange failed on server side.");
        socket_close(client_sock);
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }

    /* Receive client's username. */
    LOG_STEP("Receiving client username...");
    ssize_t n = recv(client_sock, info.remote_username, USERNAME_SIZE - 1, 0);
    if (n <= 0) {
        LOG_ERROR("Failed to receive client's username.");
        socket_close(client_sock);
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }
    info.remote_username[n] = '\0';
    LOG_INFO("Received client username: %s", info.remote_username);

    /* Send server's username back. */
    LOG_STEP("Sending server username to client...");
    if (send_all(client_sock, username, strlen(username), 0) < 0) {
        LOG_ERROR("Failed to send server username.");
        socket_close(client_sock);
        socket_close(server_socket);
        exit(EXIT_FAILURE);
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    LOG_INFO("Client '%s' connected from IP: %s", info.remote_username, client_ip);

    LOG_STEP("Starting chat session...");
    chat_session(&info);

    socket_close(server_socket);
    LOG_INFO("Server mode terminated.");
}

/* ---------------------------------------------------------------------------
 * CLIENT MODE: Prompt user for IP/Port, connect to server, do key exchange, chat.
 * --------------------------------------------------------------------------- */
static void client_mode(const char *username)
{
    LOG_STEP("Starting client mode...");
    char server_ip[256];
    int server_port;
    prompt_for_ip_and_port(server_ip, sizeof(server_ip), &server_port);

    int client_socket;
    while (1) {
        LOG_STEP("Creating client socket...");
        client_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (client_socket < 0) {
            LOG_ERROR("Could not create client socket.");
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port   = htons(server_port);

        if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
            LOG_ERROR("Invalid server IP address.");
            socket_close(client_socket);
            exit(EXIT_FAILURE);
        }

        LOG_STEP("Attempting to connect to server %s:%d...", server_ip, server_port);
        if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
            LOG_INFO("Successfully connected to server.");
            break;
        } else {
            /* If connection fails, allow user to retry or re‐enter IP/Port. */
            socket_close(client_socket);

            char choice[10];
            while (1) {
                printf("[INPUT] Type 'r' to retry or 'n' to re-enter IP/port: ");
                if (!safe_fgets(choice, sizeof(choice), stdin)) {
                    LOG_ERROR("Failed to read input.");
                    continue;
                }
                choice[strcspn(choice, "\n")] = '\0';

                if (strlen(choice) == 1 && tolower((unsigned char)choice[0]) == 'r') {
                    LOG_INFO("Retrying connection...");
                    break;
                } else if (strlen(choice) == 1 && tolower((unsigned char)choice[0]) == 'n') {
                    LOG_INFO("Re-entering IP/port...");
                    prompt_for_ip_and_port(server_ip, sizeof(server_ip), &server_port);
                    break;
                } else {
                    LOG_WARNING("Invalid input. Please try again.");
                }
            }
            /* If user typed 'r', loop tries again immediately.
               If 'n', we prompt for IP/port again, then loop continues. */
            if (tolower((unsigned char)choice[0]) == 'r') {
                continue;
            } else {
                continue;
            }
        }
    }

    chat_info info;
    memset(&info, 0, sizeof(info));
    info.sock = client_socket;
    strncpy(info.local_username, username, USERNAME_SIZE - 1);

    LOG_STEP("Performing key exchange as client...");
    if (perform_key_exchange(client_socket, username, info.remote_username, info.rx_key, info.tx_key, 0) != 0) {
        LOG_ERROR("Key exchange failed on client side.");
        socket_close(client_socket);
        exit(EXIT_FAILURE);
    }

    /* Send client's username to server. */
    LOG_STEP("Sending client username to server...");
    if (send_all(client_socket, username, strlen(username), 0) < 0) {
        LOG_ERROR("Failed to send client username.");
        socket_close(client_socket);
        exit(EXIT_FAILURE);
    }

    /* Receive server's username. */
    ssize_t n = recv(client_socket, info.remote_username, USERNAME_SIZE - 1, 0);
    if (n <= 0) {
        LOG_ERROR("Failed to receive server username.");
        socket_close(client_socket);
        exit(EXIT_FAILURE);
    }
    info.remote_username[n] = '\0';
    LOG_INFO("Received server username: %s", info.remote_username);

    LOG_STEP("Starting chat session...");
    chat_session(&info);

    LOG_INFO("Client mode terminated.");
}

/* ---------------------------------------------------------------------------
 * MAIN: Prompts for username, then for server/client mode, starts accordingly.
 * --------------------------------------------------------------------------- */
int main(void)
{
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
        printf("Press 'c' to connect as client, or press ENTER to run as server: ");
        if (!safe_fgets(choice, sizeof(choice), stdin)) {
            LOG_ERROR("Failed to read mode selection.");
            continue;
        }
        choice[strcspn(choice, "\n")] = '\0';

        /* If user presses ENTER => server mode; if 'c' => client mode. */
        if ((strlen(choice) == 0) || 
            (strlen(choice) == 1 && tolower((unsigned char)choice[0]) == 'c'))
        {
            break;
        } else {
            LOG_WARNING("Invalid input. Press 'c' for client or ENTER for server.");
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
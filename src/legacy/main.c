/******************************************************************************
 * main.c
 *
 * Pear (UDP + NAT Traversal Version)
 *
 * This version uses:
 *   1. STUN to discover your public IP/port and (optionally) detect NAT type.
 *   2. UDP hole punching to connect peers behind NATs.
 *   3. An ephemeral key exchange over UDP.
 *   4. An encrypted chat session using ChaCha20-Poly1305 once the connection is made.
 *
 * Note: Make sure you have updated nat_traversal.h (see above) so that it includes
 * the proper headers on Windows.
 ******************************************************************************/

#include "common.h"        // Common definitions, logging macros, etc.
#include "chat.h"          // chat_session(...) for sending/receiving threads
#include "crypto_utils.h"  // perform_key_exchange(...), encrypt/decrypt logic
#include "commands.h"      // process_command(...) and slash commands
#include "nat_traversal.h" // nat_get_public_info(...), hole_punch_udp(...)
#include "stun_utils.h"    // Your STUN Binding Request code (if separate)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #define close closesocket
#endif

/* ---------------------------------------------------------------------------
 * UTILITY FUNCTIONS
 * --------------------------------------------------------------------------- */

/*
 * init_sockets_and_crypto:
 *   Initializes sockets (WSAStartup on Windows) and libsodium.
 */
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

/*
 * cleanup_sockets:
 *   Cleans up sockets (WSACleanup on Windows).
 */
static void cleanup_sockets(void) {
    LOG_STEP("Cleaning up sockets...");
#ifdef _WIN32
    WSACleanup();
#endif
    LOG_INFO("Sockets cleaned up.");
}

/*
 * get_username:
 *   Prompts the user for a valid username (alphanumeric or underscore).
 */
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

/*
 * is_valid_ip / is_valid_port:
 *   Validate user input for IP and port.
 */
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

/*
 * prompt_for_ip_and_port:
 *   Prompts the user to enter a peer IP and port.
 */
static void prompt_for_ip_and_port(char *host_ip, size_t ip_size, int *host_port) {
    char port_str[10];
    while (1) {
        LOG_STEP("Prompting for peer IP...");
        printf("Enter peer IP: ");
        if (!safe_fgets(host_ip, ip_size, stdin)) {
            LOG_ERROR("Failed to read IP.");
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
        LOG_STEP("Prompting for peer port...");
        printf("Enter peer port: ");
        if (!safe_fgets(port_str, sizeof(port_str), stdin)) {
            LOG_ERROR("Failed to read port.");
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
    LOG_INFO("Peer IP and port accepted: %s:%d", host_ip, *host_port);
}

/*
 * flush_udp_socket:
 *   Reads and discards any pending data on the UDP socket.
 */
static void flush_udp_socket(int sockfd) {
    unsigned char buf[1024];
    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        struct timeval tv = {0, 0}; // immediate poll
#ifdef _WIN32
        int sel = select(0, &rfds, NULL, NULL, &tv);
#else
        int sel = select(sockfd + 1, &rfds, NULL, NULL, &tv);
#endif
        if (sel > 0 && FD_ISSET(sockfd, &rfds)) {
            ssize_t rcv = recv(sockfd, (char *)buf, sizeof(buf), 0);
            if (rcv <= 0)
                break;
        } else {
            break;
        }
    }
}

/*
 * create_bound_udp_socket:
 *   Creates a UDP socket bound to an ephemeral port.
 */
static int create_bound_udp_socket(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_ERROR("Could not create UDP socket.");
        return -1;
    }
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
#ifdef _WIN32
    local_addr.sin_addr.s_addr = INADDR_ANY;
#else
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
#endif
    local_addr.sin_port = htons(0); // ephemeral
    if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
        LOG_ERROR("UDP bind() failed.");
        socket_close(sock);
        return -1;
    }

    // Print the ephemeral port we got (for debugging)
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(sock, (struct sockaddr *)&local_addr, &addr_len) == 0) {
        int dyn_port = ntohs(local_addr.sin_port);
        LOG_INFO("Local ephemeral UDP port: %d", dyn_port);
    }
    return sock;
}

/* ---------------------------------------------------------------------------
 * SERVER MODE (UDP + NAT Traversal)
 * --------------------------------------------------------------------------- */
static void server_mode(const char *username) {
    LOG_STEP("Starting server mode (UDP + NAT Traversal)...");

    // 1) Create & bind a UDP socket
    int sockfd = create_bound_udp_socket();
    if (sockfd < 0) {
        LOG_ERROR("Server mode: Could not create/bind UDP socket.");
        return;
    }

    // 2) Use STUN to get our public info
    char public_ip[64] = {0};
    uint16_t public_port = 0;
    if (nat_get_public_info(public_ip, sizeof(public_ip), &public_port) == 0) {
        LOG_INFO("Share this public endpoint with your peer: %s:%u", public_ip, public_port);
    } else {
        LOG_WARNING("Failed to get STUN-based public endpoint. May not work behind NAT...");
    }

    // 3) Prompt for peer's public IP/port
    chat_info info;
    memset(&info, 0, sizeof(info));
    strncpy(info.local_username, username, USERNAME_SIZE - 1);
    prompt_for_ip_and_port(info.last_host_ip, sizeof(info.last_host_ip), &info.last_host_port);

    // 4) Build remote address
    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, info.last_host_ip, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(info.last_host_port);

    // 5) Hole punch with interactive retry if it fails after 30 attempts.
    LOG_STEP("Performing hole punching (server side)...");
    while (1) {
        if (hole_punch_udp(sockfd, &remote_addr, 30) == 0) {
            // Hole punching succeeded.
            break;
        }
        // Hole punching failed—prompt the user until valid input is provided.
        char choice = '\0';
        while (1) {
            char input[10];
            printf("[INPUT] Type 'r' to retry, 'n' to re-enter IP/port, and 'q' to quit: ");
            fflush(stdout);
            if (!safe_fgets(input, sizeof(input), stdin)) {
                LOG_ERROR("Failed to read input.");
                socket_close(sockfd);
                return;
            }
            input[strcspn(input, "\n")] = '\0';
            if (strlen(input) != 1) {
                LOG_WARNING("Invalid input. Please enter 'r', 'n', or 'q'.");
                continue;
            }
            choice = tolower((unsigned char)input[0]);
            if (choice == 'r' || choice == 'n' || choice == 'q') {
                break; // valid input received, break out of inner loop
            } else {
                LOG_WARNING("Invalid input. Please enter 'r', 'n', or 'q'.");
            }
        }
        // Process valid choice.
        if (choice == 'r') {
            continue; // retry hole punching
        } else if (choice == 'n') {
            prompt_for_ip_and_port(info.last_host_ip, sizeof(info.last_host_ip), &info.last_host_port);
            memset(&remote_addr, 0, sizeof(remote_addr));
            remote_addr.sin_family = AF_INET;
            inet_pton(AF_INET, info.last_host_ip, &remote_addr.sin_addr);
            remote_addr.sin_port = htons(info.last_host_port);
            continue;
        } else if (choice == 'q') {
            LOG_STEP("Quitting server mode due to hole punching failure.");
            socket_close(sockfd);
            return;
        }
    }

    // 6) Flush any stray data from the UDP socket
    flush_udp_socket(sockfd);

    // 7) Perform ephemeral key exchange (server side) over this UDP socket
    LOG_STEP("Performing ephemeral key exchange (server side)...");
    if (perform_key_exchange(sockfd, info.local_username, info.remote_username,
                             info.rx_key, info.tx_key, /*is_server=*/1) != 0)
    {
        LOG_ERROR("Key exchange failed (server).");
        socket_close(sockfd);
        return;
    }
    LOG_INFO("Key exchange succeeded. Remote user: %s", info.remote_username);

    // 8) Start the chat session
    LOG_STEP("Starting chat session...");
    info.sock = sockfd;
    chat_session(&info);

    socket_close(sockfd);
    LOG_STEP("Server mode ended.");
}

/* ---------------------------------------------------------------------------
 * CLIENT MODE (UDP + NAT Traversal)
 * --------------------------------------------------------------------------- */
static void client_mode(const char *username) {
    LOG_STEP("Starting client mode (UDP + NAT Traversal)...");

    // 1) Create & bind a UDP socket
    int sockfd = create_bound_udp_socket();
    if (sockfd < 0) {
        LOG_ERROR("Client mode: Could not create/bind UDP socket.");
        return;
    }

    // 2) Use STUN to get our public info
    char public_ip[64] = {0};
    uint16_t public_port = 0;
    if (nat_get_public_info(public_ip, sizeof(public_ip), &public_port) == 0) {
        LOG_INFO("Share this public endpoint with your peer: %s:%u", public_ip, public_port);
    } else {
        LOG_WARNING("Failed to get STUN-based public endpoint. May not work behind NAT...");
    }

    // 3) Prompt for peer's public IP/port
    chat_info info;
    memset(&info, 0, sizeof(info));
    strncpy(info.local_username, username, USERNAME_SIZE - 1);
    prompt_for_ip_and_port(info.last_host_ip, sizeof(info.last_host_ip), &info.last_host_port);

    // 4) Build remote address
    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, info.last_host_ip, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(info.last_host_port);

    // 5) Hole punch with interactive retry if it fails after 30 attempts.
    LOG_STEP("Performing hole punching (client side)...");
    while (1) {
        if (hole_punch_udp(sockfd, &remote_addr, 30) == 0) {
            // Hole punching succeeded.
            break;
        }
        // Hole punching failed—prompt the user until valid input is provided.
        char choice = '\0';
        while (1) {
            char input[10];
            printf("[INPUT] Type 'r' to retry, 'n' to re-enter IP/port, and 'q' to quit: ");
            fflush(stdout);
            if (!safe_fgets(input, sizeof(input), stdin)) {
                LOG_ERROR("Failed to read input.");
                socket_close(sockfd);
                return;
            }
            input[strcspn(input, "\n")] = '\0';
            if (strlen(input) != 1) {
                LOG_WARNING("Invalid input. Please enter 'r', 'n', or 'q'.");
                continue;
            }
            choice = tolower((unsigned char)input[0]);
            if (choice == 'r' || choice == 'n' || choice == 'q') {
                break; // valid input received
            } else {
                LOG_WARNING("Invalid input. Please enter 'r', 'n', or 'q'.");
            }
        }
        // Process valid choice.
        if (choice == 'r') {
            continue; // retry hole punching
        } else if (choice == 'n') {
            prompt_for_ip_and_port(info.last_host_ip, sizeof(info.last_host_ip), &info.last_host_port);
            memset(&remote_addr, 0, sizeof(remote_addr));
            remote_addr.sin_family = AF_INET;
            inet_pton(AF_INET, info.last_host_ip, &remote_addr.sin_addr);
            remote_addr.sin_port = htons(info.last_host_port);
            continue;
        } else if (choice == 'q') {
            LOG_STEP("Quitting client mode due to hole punching failure.");
            socket_close(sockfd);
            return;
        }
    }

    // 6) Flush any stray data from the UDP socket
    flush_udp_socket(sockfd);

    // 7) Perform ephemeral key exchange (client side) over this UDP socket
    LOG_STEP("Performing ephemeral key exchange (client side)...");
    if (perform_key_exchange(sockfd, info.local_username, info.remote_username,
                             info.rx_key, info.tx_key, /*is_server=*/0) != 0)
    {
        LOG_ERROR("Key exchange failed (client).");
        socket_close(sockfd);
        return;
    }
    LOG_INFO("Key exchange succeeded. Remote user: %s", info.remote_username);

    // 8) Start the chat session
    LOG_STEP("Starting chat session...");
    info.sock = sockfd;
    chat_session(&info);

    socket_close(sockfd);
    LOG_STEP("Client mode ended.");
}

/* ---------------------------------------------------------------------------
 * MAIN
 * --------------------------------------------------------------------------- */
int main(void) {
    LOG_STEP("Application starting...");
    init_sockets_and_crypto();

    // Prompt for username
    char username[USERNAME_SIZE];
    if (get_username(username, sizeof(username)) != 0) {
        cleanup_sockets();
        exit(EXIT_FAILURE);
    }

    // Ask user: server or client?
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
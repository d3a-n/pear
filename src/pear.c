/*******************************************************
 * Block 1: Libraries and Initial Setup (Refactored + Encryption)
 *******************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <netdb.h>
#endif

// Libsodium for Encryption & Secure Memory
#include <sodium.h>

// Buffer sizes, user constraints
#define BUFFER_SIZE 1024
#define USERNAME_SIZE 50
#define MAX_PORT 65535
#define MIN_PORT 1

// Error codes
#define ERR_SOCKET_CREATION -1
#define ERR_SOCKET_BINDING  -2
#define ERR_LISTENING       -3

// Cross-platform socket closure
#ifdef _WIN32
    #define socket_close(s) closesocket(s)
#else
    #define socket_close(s) close(s)
#endif

// --- Forward declarations (some updated for encryption flow) ---

/**
 * @brief Initializes sockets (WinSock on Windows) and libsodium.
 */
void init_sockets_and_crypto();

/**
 * @brief Cleans up sockets on all platforms (WSACleanup on Windows).
 */
void cleanup_sockets();

/**
 * @brief Display the “public” IP (local in this case) and port assigned to the server.
 */
void display_public_ip_and_port(int port);

/**
 * @brief Validates that a string is a correct IPv4 address format.
 */
int is_valid_ip(const char *ip);

/**
 * @brief Validates a port string is numeric and within acceptable range.
 */
int is_valid_port(const char *port_str);

/**
 * @brief Gets a valid username from user input.
 */
int get_username(char *username, size_t size);

/**
 * @brief Create a server socket, binds, and listens on an ephemeral port.
 */
int start_server(const char *username);

/**
 * @brief Client connect logic (retries, re-input IP/Port, immediate chat).
 */
void start_client(const char *username, const char *host_ip, int host_port);

/**
 * @brief Acquires valid IP/port from user (with input checks).
 */
int get_valid_ip_and_port(char *host_ip, int *host_port);

/**
 * @brief Closes a server socket gracefully.
 */
void stop_server(int server_socket);

/**
 * @brief Accepts an incoming connection on the server & starts a chat session.
 */
void start_chat_server(int server_socket, const char *local_username);

/**
 * @brief Threads for receiving and sending messages (with encryption).
 */
void *receive_messages(void *arg);
void *send_messages(void *arg);

// Additional forward declarations for encryption utility
int perform_key_exchange(int sock, const char *local_username, char *remote_username,
                         unsigned char *rx_key, unsigned char *tx_key, int is_server);

/**
 * @brief Encrypts a message with ChaCha20-Poly1305.
 */
int encrypt_message(const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char *key,
                    unsigned char *ciphertext, size_t *ciphertext_len);

/**
 * @brief Decrypts a message with ChaCha20-Poly1305.
 */
int decrypt_message(const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *key,
                    unsigned char *plaintext, size_t *plaintext_len);

/**
 * @brief Zeroes out any sensitive data (keys, buffers).
 */
void secure_memzero(void *v, size_t n);

/*******************************************************
 * Block 2: Initialization, Cleanup, and Utility Functions
 *******************************************************/

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "sodium.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

// We assume all the forward declarations from Block 1 are present in a header.

void init_sockets_and_crypto() {
    printf("[INFO] Initializing sockets and libsodium...\n");
#ifdef _WIN32
    WSADATA wsaData;
    int wsa_result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsa_result != 0) {
        fprintf(stderr, "[ERROR] WSAStartup failed with error code: %d\n", wsa_result);
        exit(EXIT_FAILURE);
    }
#endif

    // Initialize libsodium
    if (sodium_init() < 0) {
        fprintf(stderr, "[ERROR] libsodium initialization failed.\n");
#ifdef _WIN32
        WSACleanup();
#endif
        exit(EXIT_FAILURE);
    }

    printf("[INFO] Sockets and libsodium initialized successfully.\n");
}

void cleanup_sockets() {
    printf("[INFO] Cleaning up sockets...\n");
#ifdef _WIN32
    WSACleanup();
#endif
    printf("[INFO] Socket cleanup complete. No logs are kept at any time.\n");
}

void display_public_ip_and_port(int port) {
    printf("[INFO] Attempting to display local IP and assigned port...\n");
    char hostbuffer[256];
    struct hostent *host_entry;

    if (gethostname(hostbuffer, sizeof(hostbuffer)) == 0) {
        host_entry = gethostbyname(hostbuffer);
        if (host_entry && host_entry->h_addr_list[0]) {
            printf("[INFO] Your (local) IP: %s\n",
                   inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0])));
            printf("[INFO] Your port: %d\n", port);
        } else {
            fprintf(stderr, "[ERROR] Unable to retrieve local IP.\n");
        }
    } else {
        fprintf(stderr, "[ERROR] Unable to retrieve hostname.\n");
    }
}

int is_valid_ip(const char *ip) {
    // Basic IPv4 format check
    int period_count = 0;
    size_t len = strlen(ip);
    if (len < 7 || len > 15) {
        return 0;
    }
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

int is_valid_port(const char *port_str) {
    char *endptr;
    long port = strtol(port_str, &endptr, 10);

    if (*endptr != '\0' || port < 1 || port > 65535) {
        return 0;
    }
    return 1;
}

/**
 * @brief Securely zero out memory using libsodium’s sodium_memzero().
 */
void secure_memzero(void *v, size_t n) {
    if (v && n > 0) {
        sodium_memzero(v, n);
    }
}

int get_username(char *username, size_t size) {
    while (1) {
        printf("[INPUT] Enter your username (only letters, digits, underscores): ");
        fflush(stdout);

        if (fgets(username, size, stdin) == NULL) {
            fprintf(stderr, "[ERROR] Failed to read username from stdin.\n");
            return -1;
        }

        // Remove trailing newline
        username[strcspn(username, "\n")] = '\0';

        if (strlen(username) == 0) {
            printf("[WARNING] Username cannot be empty. Please try again.\n");
            continue;
        }

        // Validate username: only letters, digits, underscores
        int valid = 1;
        for (size_t i = 0; i < strlen(username); i++) {
            if (!isalnum((unsigned char)username[i]) && username[i] != '_') {
                valid = 0;
                break;
            }
        }
        if (!valid) {
            printf("[WARNING] Invalid username. Only letters, digits, and underscores allowed.\n");
            continue;
        }

        printf("[INFO] Username set to: %s\n", username);
        return 0;
    }
}

int get_valid_ip_and_port(char *host_ip, int *host_port) {
    while (1) {
        printf("[INPUT] Enter the server IP: ");
        fflush(stdout);

        if (fgets(host_ip, 256, stdin) == NULL) {
            fprintf(stderr, "[ERROR] Failed to read IP.\n");
            return -1;
        }
        host_ip[strcspn(host_ip, "\n")] = '\0'; // Remove newline

        if (!is_valid_ip(host_ip)) {
            printf("[WARNING] Invalid IP format. Try again.\n");
            continue;
        }

        char port_str[10];
        printf("[INPUT] Enter the server port: ");
        fflush(stdout);

        if (fgets(port_str, sizeof(port_str), stdin) == NULL) {
            fprintf(stderr, "[ERROR] Failed to read port.\n");
            return -1;
        }
        port_str[strcspn(port_str, "\n")] = '\0';

        if (!is_valid_port(port_str)) {
            printf("[WARNING] Invalid port. Must be between 1-65535. Try again.\n");
            continue;
        }

        *host_port = atoi(port_str);
        return 0;
    }
}

/*******************************************************
 * Block 3: Encryption Utility Functions (Curve25519, ChaCha20-Poly1305) [Updated]
 *******************************************************/

#include "sodium.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Forward declarations for secure_memzero, etc.
extern void secure_memzero(void *v, size_t n);

#define EPHEMERAL_KEY_SIZE crypto_kx_PUBLICKEYBYTES

/**
 * @brief Reads exactly 'length' bytes from 'sock' into 'buffer', unless
 *        the connection drops or an error occurs.
 * @return The total number of bytes read, or -1 on failure.
 */
static ssize_t read_exact(int sock, void *buffer, size_t length) {
    size_t total = 0;
    unsigned char *buf = (unsigned char*)buffer;

    while (total < length) {
        ssize_t r = recv(sock, (char*)(buf + total), length - total, 0);
        if (r <= 0) {
            // Connection closed or error
            return -1;
        }
        total += r;
    }
    return (ssize_t)total;
}

/**
 * @brief Performs a key exchange between two peers (client or server).
 *        Uses ephemeral X25519 keys from libsodium's crypto_kx API.
 *
 * @param sock            The socket descriptor over which to exchange public keys.
 * @param local_username  The local username (unused in this function).
 * @param remote_username The remote username (unused here).
 * @param rx_key          Pointer to buffer for storing the "receive" key (size=crypto_kx_SESSIONKEYBYTES).
 * @param tx_key          Pointer to buffer for storing the "transmit" key (size=crypto_kx_SESSIONKEYBYTES).
 * @param is_server       Non-zero if this side is the server, zero if client.
 * @return int            0 if success, -1 if failure.
 */
int perform_key_exchange(int sock, const char *local_username, char *remote_username,
                         unsigned char *rx_key, unsigned char *tx_key, int is_server)
{
    // Suppress unused-parameter warnings (if truly unused)
    (void)local_username;
    (void)remote_username;

    printf("[INFO] Performing ephemeral key exchange in %s mode...\n",
           is_server ? "SERVER" : "CLIENT");

    // 1) Generate ephemeral key pair
    unsigned char local_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char local_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(local_pk, local_sk);

    // 2) Send local public key to peer
    if (send(sock, (const char*)local_pk, crypto_kx_PUBLICKEYBYTES, 0) < 0) {
        fprintf(stderr, "[ERROR] Sending local public key failed (errno=%d).\n", errno);
        secure_memzero(local_sk, sizeof(local_sk));
        return -1;
    }
    printf("[INFO] Sent ephemeral public key to peer.\n");

    // 3) Receive remote public key
    unsigned char remote_pk[crypto_kx_PUBLICKEYBYTES];
    ssize_t bytes_received = read_exact(sock, remote_pk, crypto_kx_PUBLICKEYBYTES);
    if (bytes_received < (ssize_t)crypto_kx_PUBLICKEYBYTES) {
        fprintf(stderr, "[ERROR] Failed to receive remote public key (got %zd bytes, needed %d).\n",
                bytes_received, crypto_kx_PUBLICKEYBYTES);
        secure_memzero(local_sk, sizeof(local_sk));
        return -1;
    }
    printf("[INFO] Received ephemeral public key from peer.\n");

    // 4) Derive session keys
    int status;
    if (is_server) {
        status = crypto_kx_server_session_keys(rx_key, tx_key,
                                               local_pk, local_sk,
                                               remote_pk);
    } else {
        status = crypto_kx_client_session_keys(rx_key, tx_key,
                                               local_pk, local_sk,
                                               remote_pk);
    }

    // Wipe ephemeral secret key
    secure_memzero(local_sk, sizeof(local_sk));

    if (status != 0) {
        fprintf(stderr, "[ERROR] Deriving session keys failed.\n");
        return -1;
    }
    printf("[INFO] Session keys derived successfully.\n");
    return 0;
}

/**
 * @brief Encrypts a message using ChaCha20-Poly1305 AEAD with the provided key.
 */
int encrypt_message(const unsigned char *plaintext, size_t plaintext_len,
                    const unsigned char *key,
                    unsigned char *ciphertext, size_t *ciphertext_len)
{
    if (!plaintext || !key || !ciphertext || !ciphertext_len) {
        return -1;
    }

    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned long long ct_len = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext + sizeof(nonce), &ct_len,
        plaintext, plaintext_len,
        NULL, 0,     // additional data
        NULL,        // nsec
        nonce, key
    );

    // Prepend nonce
    memcpy(ciphertext, nonce, sizeof(nonce));
    *ciphertext_len = ct_len + sizeof(nonce);
    return 0;
}

/**
 * @brief Decrypts a message using ChaCha20-Poly1305 AEAD with the provided key.
 */
int decrypt_message(const unsigned char *ciphertext, size_t ciphertext_len,
                    const unsigned char *key,
                    unsigned char *plaintext, size_t *plaintext_len)
{
    if (!ciphertext || !key || !plaintext || !plaintext_len) {
        return -1;
    }

    if (ciphertext_len < crypto_aead_chacha20poly1305_IETF_NPUBBYTES) {
        return -1;
    }

    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    memcpy(nonce, ciphertext, sizeof(nonce));

    const unsigned char *enc_data = ciphertext + sizeof(nonce);
    size_t enc_len = ciphertext_len - sizeof(nonce);

    unsigned long long pt_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &pt_len,
            NULL,  // nsec
            enc_data, enc_len,
            NULL, 0, // no additional data
            nonce, key) != 0)
    {
        // Decryption failed / tampered
        return -1;
    }

    *plaintext_len = (size_t)pt_len;
    return 0;
}

/*******************************************************
 * Block 4: Server (Multi-Connection) & Client Logic [Updated for rx_key/tx_key usage]
 *******************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>

// Cross-platform includes for networking
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <netdb.h>
#endif

#include "sodium.h"

// Forward declarations from other blocks
extern void display_public_ip_and_port(int port);
extern int is_valid_ip(const char *ip);
extern int is_valid_port(const char *port_str);
extern void secure_memzero(void *v, size_t n);
extern int perform_key_exchange(int sock, const char *local_username, char *remote_username,
                                unsigned char *rx_key, unsigned char *tx_key, int is_server);
extern void chat(int socket_fd,
                 const char *local_username,
                 const char *remote_username,
                 const unsigned char *rx_key,     // new param
                 const unsigned char *tx_key);    // new param

extern int get_username(char *username, size_t size);

#define MAX_PORT         65535
#define MIN_PORT         1
#define ERR_SOCKET_CREATION -1
#define ERR_SOCKET_BINDING  -2
#define ERR_LISTENING       -3

#define BUFFER_SIZE   1024
#define USERNAME_SIZE 50
#define MAX_CLIENTS   5   // Example limit, can be adjusted

// Cross-platform socket closure
#ifdef _WIN32
    #define socket_close(s) closesocket(s)
#else
    #define socket_close(s) close(s)
#endif

// Forward references
void stop_server(int server_socket);
int get_valid_ip_and_port(char *host_ip, int *host_port);
int start_server(const char *username);
void start_chat_server(int server_socket, const char *local_username);

/**
 * @brief Thread argument for "handle_client".
 */
typedef struct {
    int  client_sock;
    char local_username[USERNAME_SIZE];
} ClientHandlerArgs;

/**
 * @brief Handles handshake & chat flow for a single client. Runs in its own thread.
 */
static void *handle_client(void *arg) {
    ClientHandlerArgs *handler_args = (ClientHandlerArgs*)arg;
    int client_sock = handler_args->client_sock;
    char local_username[USERNAME_SIZE];
    strcpy(local_username, handler_args->local_username);

    free(handler_args);

    printf("[INFO] Server: Handling new client in a separate thread.\n");

    unsigned char rx_key[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx_key[crypto_kx_SESSIONKEYBYTES];
    memset(rx_key, 0, sizeof(rx_key));
    memset(tx_key, 0, sizeof(tx_key));

    char remote_username[USERNAME_SIZE];
    memset(remote_username, 0, sizeof(remote_username));

    if (perform_key_exchange(client_sock,
                             local_username,
                             remote_username,
                             rx_key,
                             tx_key,
                             1 /* is_server */) != 0)
    {
        fprintf(stderr, "[ERROR] Server: Key exchange failed with client.\n");
        socket_close(client_sock);
        pthread_exit(NULL);
    }
    printf("[INFO] Server: Ephemeral key exchange with client done.\n");

    ssize_t valread = recv(client_sock, (char*)remote_username, USERNAME_SIZE - 1, 0);
    if (valread <= 0) {
        fprintf(stderr, "[ERROR] Server: Failed to read remote username.\n");
        socket_close(client_sock);
        pthread_exit(NULL);
    }
    remote_username[valread] = '\0';

    // Send our local username back
    if (send(client_sock, (const char*)local_username, strlen(local_username), 0) < 0) {
        fprintf(stderr, "[ERROR] Server: Failed to send local username.\n");
        socket_close(client_sock);
        pthread_exit(NULL);
    }

    // Get the client's IP address
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    if (getpeername(client_sock, (struct sockaddr*)&client_addr, &client_len) == 0) {
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("[INFO] Server: Client connected from IP: %s, Username: %s\n", client_ip, remote_username);
    } else {
        printf("[INFO] Server: Client connected, but failed to get IP address. Username: %s\n", remote_username);
    }

    chat(client_sock, local_username, remote_username, rx_key, tx_key);

    socket_close(client_sock);
    printf("[INFO] Server: Client handler thread exiting (client disconnected).\n");
    pthread_exit(NULL);
    return NULL;
}

/**
 * @brief Creates a TCP server on an ephemeral port, then listens.
 * @return Socket descriptor, or negative error code.
 */
int start_server(const char *username) {
    (void)username; // If not used here

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        fprintf(stderr, "[ERROR] start_server: Could not create socket.\n");
        return ERR_SOCKET_CREATION;
    }
    printf("[INFO] Server socket created.\n");

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(0); // ephemeral

    // Bind
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "[ERROR] start_server: Bind failed (errno=%d).\n", errno);
        socket_close(server_socket);
        return ERR_SOCKET_BINDING;
    }

    // Find assigned port
    socklen_t addr_len = sizeof(server_addr);
    if (getsockname(server_socket, (struct sockaddr*)&server_addr, &addr_len) == -1) {
        fprintf(stderr, "[ERROR] start_server: getsockname failed.\n");
        socket_close(server_socket);
        return ERR_SOCKET_BINDING;
    }
    int assigned_port = ntohs(server_addr.sin_port);

    // Show IP & Port
    display_public_ip_and_port(assigned_port);

    // Listen
    if (listen(server_socket, MAX_CLIENTS) < 0) {
        fprintf(stderr, "[ERROR] start_server: Listen failed.\n");
        socket_close(server_socket);
        return ERR_LISTENING;
    }
    printf("[INFO] Server is listening on port %d (max %d pending connections).\n",
           assigned_port, MAX_CLIENTS);

    return server_socket;
}

/**
 * @brief Accepts connections in a loop, spawns a thread for each,
 *        allowing multiple simultaneous connections.
 */
void start_chat_server(int server_socket, const char *local_username) {
    printf("[INFO] Server: Ready to accept multiple clients.\n");

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    while (1) {
        int client_sock = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            fprintf(stderr, "[ERROR] Server: Accept failed (errno=%d). Retrying...\n", errno);
            // keep going
            continue;
        }

        // Convert client IP to string
        char client_ip[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip))) {
            strcpy(client_ip, "UnknownIP");
        }
        printf("[INFO] New client connected from IP=%s\n", client_ip);

        // Create handler args
        ClientHandlerArgs *handler_args = (ClientHandlerArgs*)malloc(sizeof(ClientHandlerArgs));
        if (!handler_args) {
            fprintf(stderr, "[ERROR] Server: Memory allocation failed for handler_args.\n");
            socket_close(client_sock);
            continue;
        }
        handler_args->client_sock = client_sock;
        strncpy(handler_args->local_username, local_username, USERNAME_SIZE - 1);
        handler_args->local_username[USERNAME_SIZE - 1] = '\0';

        // Spawn thread
        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, handle_client, (void*)handler_args) != 0) {
            fprintf(stderr, "[ERROR] Server: Could not create thread for new client.\n");
            free(handler_args);
            socket_close(client_sock);
            continue;
        }
        pthread_detach(client_thread);
    }

    printf("[INFO] Server: Exiting accept loop (should rarely happen unless externally closed).\n");
}

/**
 * @brief Gracefully stops the server socket.
 */
void stop_server(int server_socket) {
    socket_close(server_socket);
    printf("[INFO] Server has been shut down.\n");
}

// ------------------------------------------------
// Client code
// ------------------------------------------------

/**
 * @brief Attempts to connect to a given host/port, does ephemeral key exchange,
 *        and starts chat upon success. Retries if user chooses.
 */
void start_client(const char *username, const char *host_ip, int host_port) {
    while (1) {
        int client_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (client_socket < 0) {
            fprintf(stderr, "[ERROR] Client: Could not create socket.\n");
            return;
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port   = htons(host_port);

        if (inet_pton(AF_INET, host_ip, &server_addr.sin_addr) <= 0) {
            fprintf(stderr, "[ERROR] Client: Invalid address: %s\n", host_ip);
            socket_close(client_socket);
            return;
        }

        printf("[INFO] Client: Connecting to %s:%d...\n", host_ip, host_port);
        if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            fprintf(stderr, "[ERROR] Client: Connection failed.\n");

            char choice[BUFFER_SIZE];
            while (1) {
                printf("[INPUT] Type 'r' to retry or 'n' to re-enter IP/port: ");
                fflush(stdout);

                if (fgets(choice, sizeof(choice), stdin)) {
                    choice[strcspn(choice, "\n")] = '\0';

                    if (strlen(choice) == 1 && tolower((unsigned char)choice[0]) == 'r') {
                        printf("[INFO] Retrying connection...\n");
                        break;
                    } else if (strlen(choice) == 1 && tolower((unsigned char)choice[0]) == 'n') {
                        char new_ip[BUFFER_SIZE];
                        int new_port;
                        if (get_valid_ip_and_port(new_ip, &new_port) == 0) {
                            printf("[INFO] Re-inputting IP/port...\n");
                            socket_close(client_socket);
                            start_client(username, new_ip, new_port);
                            return;
                        } else {
                            printf("[WARNING] Error getting new IP/port. Try again.\n");
                        }
                    } else {
                        printf("[WARNING] Invalid input. Try again.\n");
                    }
                } else {
                    printf("[ERROR] Reading from stdin failed.\n");
                }
            }
            socket_close(client_socket);
        } else {
            printf("[INFO] Client: Connected to server.\n");

            unsigned char rx_key[crypto_kx_SESSIONKEYBYTES];
            unsigned char tx_key[crypto_kx_SESSIONKEYBYTES];
            memset(rx_key, 0, sizeof(rx_key));
            memset(tx_key, 0, sizeof(tx_key));

            char remote_username[USERNAME_SIZE];
            memset(remote_username, 0, sizeof(remote_username));

            if (perform_key_exchange(client_socket,
                                     username,
                                     remote_username,
                                     rx_key,
                                     tx_key,
                                     0 /* is_server=0 */) != 0)
            {
                fprintf(stderr, "[ERROR] Client: Key exchange failed.\n");
                socket_close(client_socket);
                return;
            }
            printf("[INFO] Client: Key exchange complete.\n");

            if (send(client_socket, (const char*)username, strlen(username), 0) < 0) {
                fprintf(stderr, "[ERROR] Client: Failed to send local username.\n");
                socket_close(client_socket);
                return;
            }

            ssize_t valread = recv(client_socket, (char*)remote_username, USERNAME_SIZE - 1, 0);
            if (valread > 0) {
                remote_username[valread] = '\0';
                printf("[INFO] Client: Server username is '%s'\n", remote_username);

                chat(client_socket, username, remote_username, rx_key, tx_key);

                socket_close(client_socket);
                printf("[INFO] Client: Chat ended, returning to main.\n");
                break;
            } else {
                fprintf(stderr, "[ERROR] Client: Failed to receive server username.\n");
                socket_close(client_socket);
                return;
            }
        }
    }
}

/*******************************************************
 * Block 5: Chat Function + Main Application [Fixed “invalid input” prompt]
 *******************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <ctype.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

#include "sodium.h"

// External references from previous blocks
extern int encrypt_message(const unsigned char *plaintext, size_t plaintext_len,
                           const unsigned char *key,
                           unsigned char *ciphertext, size_t *ciphertext_len);

extern int decrypt_message(const unsigned char *ciphertext, size_t ciphertext_len,
                           const unsigned char *key,
                           unsigned char *plaintext, size_t *plaintext_len);

extern void secure_memzero(void *v, size_t n);

extern void cleanup_sockets();
extern void stop_server(int server_socket);
extern int start_server(const char *username);
extern void start_chat_server(int server_socket, const char *local_username);
extern int get_username(char *username, size_t size);
extern int get_valid_ip_and_port(char *host_ip, int *host_port);
extern void start_client(const char *username, const char *host_ip, int host_port);

/**
 * @brief ChatInfo struct with ephemeral keys.
 */
typedef struct {
    int sock;
    // Each side has already derived ephemeral session keys (rx_key, tx_key)
    // in perform_key_exchange(). We'll store them here if we want to encrypt.
    unsigned char rx_key[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx_key[crypto_kx_SESSIONKEYBYTES];
    char local_username[50];
    char remote_username[50];
} ChatInfo;

// Forward declarations for threads
void *receive_messages(void *arg);
void *send_messages(void *arg);

/**
 * @brief Spawns two threads for chat. 
 *        Currently, encryption usage is minimal (plaintext is sent).
 *        However, ephemeral keys are available if you want to integrate.
 *
 * @param socket_fd       The socket for communication
 * @param local_username  The local user’s name
 * @param remote_username The remote user’s name
 * @param rx_key          The ephemeral “receive” key
 * @param tx_key          The ephemeral “transmit” key
 */
void chat(int socket_fd, 
          const char *local_username,
          const char *remote_username,
          const unsigned char *rx_key,
          const unsigned char *tx_key)
{
    printf("[INFO] Starting chat session...\n");

    ChatInfo *info = (ChatInfo*)malloc(sizeof(ChatInfo));
    if (!info) {
        fprintf(stderr, "[ERROR] Could not allocate memory for ChatInfo.\n");
        return;
    }
    memset(info, 0, sizeof(ChatInfo));

    info->sock = socket_fd;
    strncpy(info->local_username, local_username, sizeof(info->local_username) - 1);
    strncpy(info->remote_username, remote_username, sizeof(info->remote_username) - 1);

    // Copy ephemeral keys if needed for actual encryption
    if (rx_key && tx_key) {
        memcpy(info->rx_key, rx_key, crypto_kx_SESSIONKEYBYTES);
        memcpy(info->tx_key, tx_key, crypto_kx_SESSIONKEYBYTES);
    }

    pthread_t receive_thread, send_thread;

    if (pthread_create(&receive_thread, NULL, receive_messages, (void*)info) != 0) {
        fprintf(stderr, "[ERROR] Failed to create receive_messages thread.\n");
        free(info);
        return;
    }

    if (pthread_create(&send_thread, NULL, send_messages, (void*)info) != 0) {
        fprintf(stderr, "[ERROR] Failed to create send_messages thread.\n");
        pthread_cancel(receive_thread);
        free(info);
        return;
    }

    // Wait for both threads
    pthread_join(receive_thread, NULL);
    pthread_join(send_thread, NULL);

    // Cleanup
    secure_memzero(info, sizeof(ChatInfo));
    free(info);

    printf("[INFO] Chat session ended, returning.\n");
}

/**
 * @brief Receives messages in a loop, currently treating all data as plaintext.
 */
void *receive_messages(void *arg) {
    ChatInfo *info = (ChatInfo*)arg;
    int sock = info->sock;

    unsigned char buf[1024 + crypto_aead_chacha20poly1305_IETF_ABYTES +
                      crypto_aead_chacha20poly1305_IETF_NPUBBYTES];

    while (1) {
        ssize_t bytes_received = recv(sock, (char*)buf, sizeof(buf), 0);
        if (bytes_received > 0) {
            buf[bytes_received] = '\0';
            printf("\n<%s> %s\n", info->remote_username, (char*)buf);

            // Re-print local prompt
            printf("<%s> ", info->local_username);
            fflush(stdout);
        } else if (bytes_received == 0) {
            printf("\n[INFO] Connection closed by peer.\n");
            socket_close(sock);
            pthread_exit(NULL);
        } else {
            fprintf(stderr, "\n[ERROR] Receive failed or connection dropped.\n");
            socket_close(sock);
            pthread_exit(NULL);
        }
    }
    return NULL; // unreachable
}

/**
 * @brief Sends messages from stdin in a loop, with slash commands for /quit, etc.
 */
void *send_messages(void *arg) {
    ChatInfo *info = (ChatInfo*)arg;
    int sock = info->sock;

    char input_buf[1024];
    while (1) {
        // prompt
        printf("<%s> ", info->local_username);
        fflush(stdout);

        if (!fgets(input_buf, sizeof(input_buf), stdin)) {
            fprintf(stderr, "\n[ERROR] Reading from stdin failed.\n");
            break;
        }

        input_buf[strcspn(input_buf, "\n")] = '\0';

        // Empty input -> skip
        if (strlen(input_buf) == 0) {
            continue;
        }

        // Slash command checks
        if (input_buf[0] == '/') {
            // e.g. /quit, /help, /clear
            if (strcasecmp(input_buf, "/quit") == 0) {
                printf("[INFO] Quitting chat on user request...\n");
                break;
            } else if (strcasecmp(input_buf, "/help") == 0) {
                printf("[INFO] Commands: /quit, /help, /clear\n");
                continue;
            } else if (strcasecmp(input_buf, "/clear") == 0) {
#ifdef _WIN32
                system("cls");
#else
                system("clear");
#endif
                continue;
            } else {
                printf("[INFO] Unknown command: %s\n", input_buf);
                continue;
            }
        }

        // Send plaintext
        if (send(sock, input_buf, strlen(input_buf), 0) < 0) {
            fprintf(stderr, "[ERROR] Sending message failed.\n");
            break;
        }
    }

    // graceful close
    socket_close(sock);
    pthread_exit(NULL);
    return NULL;
}

// ==========================================================
// MAIN FUNCTION (Fixed invalid “c” input handling)
// ==========================================================
int main() {
    // Initialize sockets & libsodium
    init_sockets_and_crypto();
    printf("[INFO] Starting peer-to-peer chat application...\n");

    char username[50];
    if (get_username(username, sizeof(username)) != 0) {
        cleanup_sockets();
        return EXIT_FAILURE;
    }

    // By default, start a server
    int server_socket = start_server(username);
    if (server_socket < 0) {
        cleanup_sockets();
        return EXIT_FAILURE;
    }

    // We re-prompt if user enters invalid input (not 'c' or Enter)
    while (1) {
        printf("[INPUT] Press 'c' to become a client, or just press ENTER to remain server: ");
        fflush(stdout);

        char choice[64];
        if (!fgets(choice, sizeof(choice), stdin)) {
            fprintf(stderr, "[ERROR] Reading input failed.\n");
            continue; // re-prompt
        }
        choice[strcspn(choice, "\n")] = '\0';

        // 1) If user typed nothing => remain server
        if (strlen(choice) == 0) {
            printf("[INFO] Running as SERVER. Waiting for incoming connections...\n");
            start_chat_server(server_socket, username);
            stop_server(server_socket);
            cleanup_sockets();
            return EXIT_SUCCESS;
        }
        // 2) If user typed 'c' => become client
        else if (strlen(choice) == 1 && tolower((unsigned char)choice[0]) == 'c') {
            stop_server(server_socket);
            char host_ip[256];
            int host_port;
            if (get_valid_ip_and_port(host_ip, &host_port) != 0) {
                printf("[ERROR] Invalid IP/port.\n");
                cleanup_sockets();
                return EXIT_FAILURE;
            }
            start_client(username, host_ip, host_port);
            cleanup_sockets();
            return EXIT_SUCCESS;
        }
        // 3) Anything else => re-prompt instead of quitting
        else {
            printf("[WARNING] Invalid input. Please try again.\n");
        }
    }
    // Unreachable
    return EXIT_FAILURE;
}

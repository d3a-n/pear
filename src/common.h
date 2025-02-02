#ifndef COMMON_H
#define COMMON_H

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <errno.h>
#include <sodium.h>

#define BUFFER_SIZE 1024
#define USERNAME_SIZE 50
#define MAX_PORT 65535
#define MIN_PORT 1

#define ERR_SOCKET_CREATION -1
#define ERR_SOCKET_BINDING  -2
#define ERR_LISTENING       -3

#ifdef _WIN32
  #define socket_close(s) closesocket(s)
#else
  #define socket_close(s) close(s)
#endif

// Structure representing a chat session.
typedef struct ChatInfo {
    int sock;
    unsigned char rx_key[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx_key[crypto_kx_SESSIONKEYBYTES];
    char local_username[USERNAME_SIZE];
    char remote_username[USERNAME_SIZE];
    char last_host_ip[256];
    int last_host_port;
} ChatInfo;

// Structure representing a connected client (for potential future multi-client use).
typedef struct Client {
    int sock;
    char username[USERNAME_SIZE];
    struct sockaddr_in addr;
    int muted; // Currently unused; reserved for future use.
    struct Client* next;
} Client;

// Structure representing a banned user.
typedef struct Ban {
    char username[USERNAME_SIZE];
    struct Ban* next;
} Ban;

extern Client* client_list;
extern pthread_mutex_t client_list_mutex;

extern Ban* ban_list;
extern pthread_mutex_t ban_list_mutex;

#endif // COMMON_H

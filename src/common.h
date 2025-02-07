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

/* ---------------------------------------------------------------------------
 * LOGGING MACROS
 * --------------------------------------------------------------------------- */
#define LOG_STEP(fmt, ...)    fprintf(stdout, "[STEP] " fmt "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)    fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARNING(fmt, ...) fprintf(stdout, "[WARNING] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)   fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

/* ---------------------------------------------------------------------------
 * CONSTANTS & DEFINES
 * --------------------------------------------------------------------------- */
#define BUFFER_SIZE    1024
#define USERNAME_SIZE  50

#ifdef _WIN32
  #define socket_close(s) closesocket(s)
#else
  #define socket_close(s) close(s)
#endif

/* ---------------------------------------------------------------------------
 * DATA STRUCTURES
 * --------------------------------------------------------------------------- */
/* Represents a single peer-to-peer chat session. */
typedef struct chat_info {
    int  sock;
    unsigned char rx_key[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx_key[crypto_kx_SESSIONKEYBYTES];
    char local_username[USERNAME_SIZE];
    char remote_username[USERNAME_SIZE];
    char last_host_ip[256];
    int  last_host_port;
} chat_info;

/* ---------------------------------------------------------------------------
 * FUNCTION PROTOTYPES
 * --------------------------------------------------------------------------- */
/* Sends all data in 'buf' reliably, handling partial sends. */
ssize_t send_all(int sock, const void *buf, size_t len, int flags);

/* Safely reads a line from 'stream' into 'buffer'. */
int safe_fgets(char *buffer, size_t size, FILE *stream);

#endif // COMMON_H
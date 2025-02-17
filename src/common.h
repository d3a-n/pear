#ifndef COMMON_H
#define COMMON_H

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sodium.h>
#include <pthread.h>
#include <stdint.h>

/* Logging macros */
#define LOG_STEP(fmt, ...)    fprintf(stdout, "[STEP] " fmt "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)    fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)
#define LOG_WARNING(fmt, ...) fprintf(stdout, "[WARNING] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)   fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

/* Constants */
#define BUFFER_SIZE   1024
#define USERNAME_SIZE 50

#ifdef _WIN32
  #define socket_close(s) closesocket(s)
#else
  #define socket_close(s) close(s)
#endif

/* Chat session structure */
typedef struct chat_info {
    int sock;
    unsigned char rx_key[32];
    unsigned char tx_key[32];
    char local_username[USERNAME_SIZE];
    char remote_username[USERNAME_SIZE];
    char last_host_ip[256];
    int  last_host_port;
} chat_info;

/* Function prototypes */
int safe_fgets(char *buffer, size_t size, FILE *stream);
ssize_t send_all(int sock, const void *buf, size_t len, int flags);

#endif // COMMON_H